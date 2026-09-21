// 7-tier classification (decision D040; product plan §11.7 tier table,
// which is normative). Every tier's CopyCommand is the exact native
// command from that table; multiple items collapse to one command with
// the plan's prune semantics where a native prune exists (tier 0) and
// explicit ids otherwise. Nothing here ever executes anything.
//
// Honesty rules baked into classification:
//
//   - Unknown timestamps never classify as stale (dangling/age tiers
//     require a parsed creation or last-used time).
//   - Unknown correlation never fabricates one: images that correlate to
//     no workspace AND are not upstream-registry-shaped stay
//     unclassified and are counted in a warning.
//   - Stopped containers or named volumes whose compose working_dir
//     still exists but matches no scanned root are SHIELDED (somebody's
//     unscanned project), not recommended.
//   - Tier 3 never emits a destructive command: CopyCommand is the
//     freeze-flow placeholder owned by the freeze worker.
package dockeradapter

import (
	"fmt"
	"strings"
	"time"
)

// Tier identifiers (D040 taxonomy).
const (
	TierDeadClutter       = 0
	TierStaleBuildKit     = 1
	TierZombieContainers  = 2
	TierColdProjectImages = 3
	TierDormantUpstream   = 4
	TierHostVHDXSlack     = 5
	TierOrphanedVolumes   = 6
)

// Age thresholds (D040 table): BuildKit staleness 14d, image dormancy
// 60d, active-workspace shield 14d.
const (
	buildKitStaleAge = 14 * 24 * time.Hour
	dormantImageAge  = 60 * 24 * time.Hour
)

// Output bounds: per-tier item cap and per-command id cap (the command
// line must stay comfortably inside Windows' 8191-char console limit).
const (
	maxItemsPerTier = 500
	maxCommandIDs   = 64
)

const unclassifiedImageNote = "docker: %d image(s) unclassified (no workspace correlation, not a recognized upstream base image); left untouched"

// Copyable commands (exact native forms from the plan table).
const (
	cmdImagePrune   = "docker image prune -f"
	cmdVolumePrune  = "docker volume prune -f"
	cmdBuilderPrune = `docker builder prune --filter "until=336h"`
	cmdHostSlack    = "wsl --shutdown; wsl --manage docker-desktop --set-sparse true; wsl -d docker-desktop fstrim -v /"
	// freezePlaceholder is the tier 3 stand-in until the freeze worker
	// lands the real vault pipeline; the orchestrator reconciles it.
	freezePlaceholder = "ebb freeze"

	tierDetailFreeze = "freeze-to-vault candidate: streamed docker save into the vault (SHA-256 verified in flight), 1-command restore via restic dump | docker load — then docker rmi"
)

// Compose label keys.
const (
	labelWorkingDir = "com.docker.compose.project.working_dir"
	labelProject    = "com.docker.compose.project"
	// labelVolumeWorkingDir: compose >= 2.30 records the project's
	// working dir on volumes too; older daemons leave it unset and the
	// container cross-reference fills the gap.
	labelVolumeWorkingDir = "com.docker.compose.projectworkingdir"
)

// knownOfficialBases is the offline allowlist of official-image base
// names tier 4 may treat as "upstream registry shaped" (plan examples:
// postgres, redis, node). The real official-images index is a network
// resource this engine must never touch, so anything absent here is
// honestly unclassified instead of guessed deletable — the same
// preservation-first trade as .gitignore (Foundation I-series).
var knownOfficialBases = map[string]bool{
	"alpine": true, "amazonlinux": true, "busybox": true, "caddy": true,
	"centos": true, "cirros": true, "debian": true, "docker": true,
	"eclipse-mosquitto": true, "fedora": true, "golang": true,
	"haproxy": true, "hello-world": true, "httpd": true, "influxdb": true,
	"jetty": true, "kapacitor": true, "logstash": true, "mariadb": true,
	"memcached": true, "mono": true, "mysql": true, "nats": true,
	"neo4j": true, "nginx": true, "node": true, "openjdk": true,
	"opensuse": true, "oraclelinux": true, "percona": true, "perl": true,
	"php": true, "phpmyadmin": true, "postgres": true, "python": true,
	"r-base": true, "rabbitmq": true, "redis": true, "rockylinux": true,
	"ruby": true, "rust": true, "sentry": true, "solr": true,
	"sonarqube": true, "splunk": true, "swift": true, "telegraf": true,
	"tomcat": true, "traefik": true, "ubuntu": true, "varnish": true,
	"wordpress": true, "zookeeper": true,
}

// upstreamShaped reports whether a repository reference looks like a
// pullable upstream image: a known official-library name (with or
// without the library/ or docker.io spelling), or any reference whose
// first segment is a registry host (contains "." or ":" or is
// "localhost"). Two-segment user namespaces without a host are
// deliberately ambiguous (could be an unpublished local build) and do
// NOT qualify.
func upstreamShaped(repo string) bool {
	repo = strings.TrimSpace(repo)
	if repo == "" || repo == "<none>" {
		return false
	}
	segs := strings.Split(strings.ReplaceAll(repo, "\\", "/"), "/")
	first := segs[0]
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return true
	}
	base := segs[len(segs)-1]
	if knownOfficialBases[strings.ToLower(base)] {
		return true
	}
	if (first == "docker.io" || first == "registry.hub.docker.com") &&
		(len(segs) == 2 || (len(segs) == 3 && segs[1] == "library")) {
		return true
	}
	return false
}

// classify runs the whole taxonomy. Tier 5 (host VHDX slack) is
// platform-gated and assembled by the Engine; this returns tiers
// 0,1,2,3,4,6 in order.
func classify(s *snapshot, ix *workspaceIndex, now time.Time) ([]DockerTier, []string) {
	var warnings []string
	usage := buildUsage(s)
	tiers := []DockerTier{
		classifyDeadClutter(s),
		classifyStaleBuildKit(s, now),
		classifyZombies(s, ix, &warnings),
		classifyColdImages(s, ix, usage, now),
		classifyDormantUpstream(s, ix, usage, now, &warnings),
		classifyOrphanVolumes(s, ix, usage, &warnings),
	}
	for i := range tiers {
		truncateItems(&tiers[i], &warnings)
	}
	return tiers, warnings
}

// truncateItems caps one tier at maxItemsPerTier and records the loss.
func truncateItems(t *DockerTier, warnings *[]string) {
	if len(t.Items) <= maxItemsPerTier {
		return
	}
	lost := len(t.Items) - maxItemsPerTier
	t.Items = t.Items[:maxItemsPerTier]
	*warnings = append(*warnings, fmt.Sprintf(
		"docker: tier %d (%s) truncated from %d to %d items", t.Tier, t.Title, len(t.Items)+lost, maxItemsPerTier))
}

// usage indexes container references by image ref and image id plus the
// raw records for provenance correlation.
type imageUsage struct {
	byRef  map[string][]containerRec // image ref -> referencing containers
	byID   map[string][]containerRec // 12-char id prefix -> referencing containers
	wdByPr map[string]string         // compose project -> working_dir
}

func buildUsage(s *snapshot) *imageUsage {
	u := &imageUsage{
		byRef:  map[string][]containerRec{},
		byID:   map[string][]containerRec{},
		wdByPr: map[string]string{},
	}
	for _, c := range s.containers {
		u.byRef[c.Image] = append(u.byRef[c.Image], c)
		if id := shortID(c.ID); id != "" {
			u.byID[id] = append(u.byID[id], c)
		}
		if p := c.Labels[labelProject]; p != "" {
			if wd := c.Labels[labelWorkingDir]; wd != "" {
				if _, seen := u.wdByPr[p]; !seen {
					u.wdByPr[p] = wd
				}
			}
		}
	}
	return u
}

// recordsOf returns every container record referencing one image row
// (by ref or image-id prefix).
func (u *imageUsage) recordsOf(img imageRec) []containerRec {
	out := append([]containerRec(nil), u.byRef[imageRef(img)]...)
	out = append(out, u.byID[shortID(img.ID)]...)
	return out
}

// refs splits the referencing containers into running and stopped names.
func (u *imageUsage) refs(img imageRec) (running, stopped []string) {
	for _, c := range u.recordsOf(img) {
		name := firstName(c.Names)
		if name == "" {
			name = shortID(c.ID)
		}
		if c.State == "running" {
			running = append(running, name)
		} else if c.State == "exited" || strings.HasPrefix(c.Status, "Exited") {
			stopped = append(stopped, name)
		}
	}
	return running, stopped
}

// correlateImage resolves an image to a workspace through container
// compose provenance (any container, running or stopped, whose image
// ref/id matches and whose working_dir correlates to a scanned root).
func (u *imageUsage) correlateImage(img imageRec, ix *workspaceIndex) (wsEntry, bool) {
	for _, c := range u.recordsOf(img) {
		wd := c.Labels[labelWorkingDir]
		if wd == "" {
			continue
		}
		if entry, ok := ix.matchPath(wd); ok {
			return entry, true
		}
	}
	return wsEntry{}, false
}

func imageRef(img imageRec) string {
	if img.Tag == "" || img.Tag == "<none>" {
		return img.Repository
	}
	return img.Repository + ":" + img.Tag
}

func firstName(names string) string {
	if i := strings.IndexByte(names, ','); i >= 0 {
		return names[:i]
	}
	return names
}

func isStopped(c containerRec) bool {
	return c.State == "exited" || strings.HasPrefix(c.Status, "Exited")
}

// ---- tier 0: pure dead clutter ---------------------------------------

func classifyDeadClutter(s *snapshot) DockerTier {
	t := DockerTier{Tier: TierDeadClutter, Title: "Pure Dead Clutter"}
	seenDangling := map[string]bool{}
	var imageIDs int
	for _, img := range s.images {
		if img.Repository != "<none>" || img.Tag != "<none>" {
			continue
		}
		id := shortID(img.ID)
		if id == "" || seenDangling[id] {
			continue
		}
		seenDangling[id] = true
		imageIDs++
		t.Items = append(t.Items, DockerItem{
			ID:     id,
			Detail: fmt.Sprintf("dangling image %s (%s, untagged & unreferenced)", id, formatBytes(int64(img.Size))),
		})
	}
	var volumeCount int
	for _, v := range s.volumes {
		if !isAnonymousVolumeName(v.Name) || v.Links > 0 || hasComposeLabel(v.Labels) {
			continue // only truly orphaned anonymous volumes are dead
		}
		volumeCount++
		t.Items = append(t.Items, DockerItem{
			ID:     v.Name,
			Detail: "anonymous volume (64-hex name, no container links, no labels) — size not reported by docker",
		})
	}
	switch {
	case imageIDs > 0 && volumeCount > 0:
		t.CopyCommand = cmdImagePrune + " && " + cmdVolumePrune
	case imageIDs > 0:
		t.CopyCommand = cmdImagePrune
	case volumeCount > 0:
		t.CopyCommand = cmdVolumePrune
	}
	return t
}

func hasComposeLabel(labels map[string]string) bool {
	for k := range labels {
		if strings.HasPrefix(k, "com.docker.compose.") {
			return true
		}
	}
	return false
}

// ---- tier 1: stale BuildKit cache ------------------------------------

func classifyStaleBuildKit(s *snapshot, now time.Time) DockerTier {
	t := DockerTier{Tier: TierStaleBuildKit, Title: "Stale BuildKit Cache"}
	if !s.buildxOK {
		return t
	}
	for _, rec := range s.buildx {
		var stamp time.Time
		switch {
		case !rec.LastUsed.IsZero():
			stamp = rec.LastUsed
		case !rec.Created.IsZero():
			stamp = rec.Created
		default:
			continue // unknown age: never classified stale
		}
		if now.Sub(stamp) <= buildKitStaleAge {
			continue
		}
		t.Items = append(t.Items, DockerItem{
			ID: shortID(rec.ID),
			Detail: fmt.Sprintf("buildkit cache %s (%s, %s) — last used %s",
				recordTypeLabel(rec.RecordType), formatBytes(rec.Size),
				shortID(rec.ID), daysAgo(now.Sub(stamp))),
		})
	}
	if hasRecommendable(t) {
		t.CopyCommand = cmdBuilderPrune
	}
	return t
}

func recordTypeLabel(rt string) string {
	if rt == "" {
		return "untyped record"
	}
	return rt
}

// ---- tier 2: zombie container blockers --------------------------------

func classifyZombies(s *snapshot, ix *workspaceIndex, warnings *[]string) DockerTier {
	t := DockerTier{Tier: TierZombieContainers, Title: "Zombie Container Blockers"}
	var stoppedNoProvenance int
	for _, c := range s.containers {
		if !isStopped(c) {
			continue
		}
		wd := c.Labels[labelWorkingDir]
		if wd == "" {
			stoppedNoProvenance++
			continue
		}
		name := firstName(c.Names)
		if name == "" {
			name = shortID(c.ID)
		}
		entry, matched, exists := ix.correlateDockerPath(wd)
		switch {
		case !exists:
			t.Items = append(t.Items, DockerItem{
				ID: shortID(c.ID),
				Detail: fmt.Sprintf("exited container %q (image %s) — compose working dir no longer exists: %s",
					name, c.Image, displayPath(wd)),
			})
		case matched && entry.Active:
			t.Items = append(t.Items, DockerItem{
				ID:     shortID(c.ID),
				Detail: fmt.Sprintf("exited container %q — working dir belongs to a live workspace", name),
				Shield: "active workspace: " + entry.Root,
			})
		case matched:
			t.Items = append(t.Items, DockerItem{
				ID:     shortID(c.ID),
				Detail: fmt.Sprintf("exited container %q — working dir exists in a scanned (dormant) workspace", name),
				Shield: "workspace exists: " + entry.Root,
			})
		default:
			t.Items = append(t.Items, DockerItem{
				ID:     shortID(c.ID),
				Detail: fmt.Sprintf("exited container %q — working dir exists but was not among the scanned workspace roots", name),
				Shield: "working dir outside scanned roots: " + displayPath(wd),
			})
		}
	}
	if stoppedNoProvenance > 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"docker: %d stopped container(s) without compose provenance left unclassified", stoppedNoProvenance))
	}
	if hasRecommendable(t) {
		t.CopyCommand = "docker rm " + joinIDs(collectIDs(t))
	}
	return t
}

// ---- tier 3: cold project images (freeze-to-vault candidates) ---------

func classifyColdImages(s *snapshot, ix *workspaceIndex, usage *imageUsage, now time.Time) DockerTier {
	t := DockerTier{Tier: TierColdProjectImages, Title: "Cold Project Images"}
	for _, img := range s.images {
		if img.Repository == "<none>" {
			continue // dangling handled by tier 0
		}
		// Correlation: container provenance first (strongest signal),
		// then compose-style name derivation.
		entry, correlated := usage.correlateImage(img, ix)
		if !correlated {
			entry, correlated = ix.matchName(img.Repository)
		}
		if !correlated {
			continue // tier 4 decides upstream shaping / unclassified
		}
		created, ok := imageCreatedAt(img, now)
		if !ok {
			// Correlated but unknown age: shield, never recommend.
			t.Items = append(t.Items, DockerItem{
				ID:     shortID(img.ID),
				Detail: fmt.Sprintf("image %s (%s) — creation date unknown", imageRef(img), formatBytes(int64(img.Size))),
				Shield: "unknown image age: " + entry.Root,
			})
			continue
		}
		running, _ := usage.refs(img)
		switch {
		case len(running) > 0:
			t.Items = append(t.Items, DockerItem{
				ID:     shortID(img.ID),
				Detail: fmt.Sprintf("image %s (%s, created %s) — in use", imageRef(img), formatBytes(int64(img.Size)), daysAgo(now.Sub(created))),
				Shield: "in use by running container: " + strings.Join(running, ", "),
			})
		case entry.Active:
			t.Items = append(t.Items, DockerItem{
				ID:     shortID(img.ID),
				Detail: fmt.Sprintf("image %s (%s, created %s) — workspace active within 14d", imageRef(img), formatBytes(int64(img.Size)), daysAgo(now.Sub(created))),
				Shield: "active workspace: " + entry.Root,
			})
		case now.Sub(created) > dormantImageAge:
			t.Items = append(t.Items, DockerItem{
				ID: shortID(img.ID),
				Detail: fmt.Sprintf("image %s (%s, created %s; workspace %s last touched %s) — %s",
					imageRef(img), formatBytes(int64(img.Size)), daysAgo(now.Sub(created)),
					entry.Base, daysAgo(now.Sub(entry.LastUse)), tierDetailFreeze),
			})
		default:
			// Correlated to a dormant workspace but recently built: not
			// clutter yet; omitted to keep the tier actionable.
		}
	}
	if hasRecommendable(t) {
		t.CopyCommand = freezePlaceholder + " " + joinIDs(collectIDs(t))
	}
	return t
}

// ---- tier 4: dormant upstream base images ------------------------------

func classifyDormantUpstream(s *snapshot, ix *workspaceIndex, usage *imageUsage, now time.Time, warnings *[]string) DockerTier {
	t := DockerTier{Tier: TierDormantUpstream, Title: "Dormant Upstream Base Images"}
	unclassified := 0
	var refs []string
	seenRef := map[string]bool{}
	for _, img := range s.images {
		if img.Repository == "<none>" {
			continue
		}
		if _, correlated := usage.correlateImage(img, ix); correlated {
			continue // tier 3 territory
		}
		if _, correlated := ix.matchName(img.Repository); correlated {
			continue
		}
		if !upstreamShaped(img.Repository) {
			unclassified++
			continue
		}
		created, ok := imageCreatedAt(img, now)
		if !ok {
			unclassified++
			continue
		}
		if now.Sub(created) <= dormantImageAge {
			continue // not dormant yet
		}
		running, stopped := usage.refs(img)
		switch {
		case len(running) > 0:
			continue // in use: simply not clutter
		case len(stopped) > 0:
			t.Items = append(t.Items, DockerItem{
				ID: shortID(img.ID),
				Detail: fmt.Sprintf("upstream image %s (%s, created %s) — pinned by stopped container(s); clear the tier 2 zombies first",
					imageRef(img), formatBytes(int64(img.Size)), daysAgo(now.Sub(created))),
				Shield: "blocked by stopped container: " + strings.Join(stopped, ", "),
			})
		default:
			t.Items = append(t.Items, DockerItem{
				ID: shortID(img.ID),
				Detail: fmt.Sprintf("upstream image %s (%s, created %s) — re-pullable from its registry",
					imageRef(img), formatBytes(int64(img.Size)), daysAgo(now.Sub(created))),
			})
			if ref := imageRef(img); !seenRef[ref] {
				seenRef[ref] = true
				refs = append(refs, ref)
			}
		}
	}
	if unclassified > 0 {
		*warnings = append(*warnings, fmt.Sprintf(unclassifiedImageNote, unclassified))
	}
	if len(refs) > 0 {
		t.CopyCommand = "docker rmi " + joinIDs(refs)
	}
	return t
}

// ---- tier 6: orphaned project volumes ----------------------------------

func classifyOrphanVolumes(s *snapshot, ix *workspaceIndex, usage *imageUsage, warnings *[]string) DockerTier {
	t := DockerTier{Tier: TierOrphanedVolumes, Title: "Orphaned Project Volumes"}
	var noWorkingDir int
	var nonCompose int
	for _, v := range s.volumes {
		if isAnonymousVolumeName(v.Name) {
			continue // tier 0 handled anonymous volumes
		}
		project := v.Labels[labelProject]
		if project == "" {
			nonCompose++
			continue
		}
		wd := v.Labels[labelVolumeWorkingDir]
		if wd == "" {
			wd = usage.wdByPr[project]
		}
		if wd == "" {
			noWorkingDir++
			continue
		}
		entry, matched, exists := ix.correlateDockerPath(wd)
		switch {
		case !exists:
			t.Items = append(t.Items, DockerItem{
				ID: v.Name,
				Detail: fmt.Sprintf("compose volume of project %q — project dir no longer exists: %s — back up before removal (vault volume snapshot), then remove",
					project, displayPath(wd)),
			})
		case matched && entry.Active:
			t.Items = append(t.Items, DockerItem{
				ID:     v.Name,
				Detail: fmt.Sprintf("compose volume of project %q — workspace still live", project),
				Shield: "active workspace: " + entry.Root,
			})
		case matched:
			t.Items = append(t.Items, DockerItem{
				ID:     v.Name,
				Detail: fmt.Sprintf("compose volume of project %q — workspace exists (dormant)", project),
				Shield: "workspace exists: " + entry.Root,
			})
		default:
			t.Items = append(t.Items, DockerItem{
				ID:     v.Name,
				Detail: fmt.Sprintf("compose volume of project %q — project dir exists outside the scanned workspace roots", project),
				Shield: "outside scanned roots: " + displayPath(wd),
			})
		}
	}
	if noWorkingDir > 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"docker: %d named compose volume(s) with no resolvable working dir left unclassified", noWorkingDir))
	}
	if nonCompose > 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"docker: %d named volume(s) without compose provenance left unclassified", nonCompose))
	}
	if hasRecommendable(t) {
		var names []string
		for _, item := range t.Items {
			if item.Shield == "" {
				names = append(names, item.ID)
			}
		}
		t.CopyCommand = "docker volume rm " + joinIDs(names)
	}
	return t
}

// ---- shared helpers ----------------------------------------------------

// hasRecommendable reports whether at least one item carries no shield.
func hasRecommendable(t DockerTier) bool {
	for _, item := range t.Items {
		if item.Shield == "" {
			return true
		}
	}
	return false
}

// collectIDs returns the recommendable (unshielded) item ids of a tier.
func collectIDs(t DockerTier) []string {
	ids := make([]string, 0, len(t.Items))
	for _, item := range t.Items {
		if item.Shield == "" {
			ids = append(ids, item.ID)
		}
	}
	return ids
}
