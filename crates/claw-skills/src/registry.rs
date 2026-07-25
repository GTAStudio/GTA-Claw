//! Frozen bundled-skill identity registry.

/// Executable coverage for a bundled skill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillImplementation {
    /// Metadata is registered but upstream instructions still require a reviewed
    /// native Rust, declarative HTTP, or Wasm implementation.
    RequiresNativePort,
}

/// Exact frozen identity and source metadata for one bundled skill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SkillDescriptor {
    /// Frozen inventory record identifier.
    pub record_id: &'static str,
    /// Exact bundled skill identifier.
    pub id: &'static str,
    /// Frozen classification.
    pub classification: &'static str,
    /// Frozen upstream source path.
    pub source_path: &'static str,
    /// Frozen source license.
    pub license: &'static str,
    /// Honest executable coverage.
    pub implementation: SkillImplementation,
}

macro_rules! skill {
    ($id:literal) => {
        SkillDescriptor {
            record_id: concat!("skill:", $id),
            id: $id,
            classification: "official_integration",
            source_path: concat!("skills/", $id, "/SKILL.md"),
            license: "MIT",
            implementation: SkillImplementation::RequiresNativePort,
        }
    };
    ($id:literal, $license:literal) => {
        SkillDescriptor {
            record_id: concat!("skill:", $id),
            id: $id,
            classification: "official_integration",
            source_path: concat!("skills/", $id, "/SKILL.md"),
            license: $license,
            implementation: SkillImplementation::RequiresNativePort,
        }
    };
}

static REGISTRY: [SkillDescriptor; 51] = [
    skill!("1password"),
    skill!("apple-notes"),
    skill!("apple-reminders"),
    skill!("bear-notes"),
    skill!("blogwatcher"),
    skill!("blucli"),
    skill!("camsnap"),
    skill!("clawhub"),
    skill!("coding-agent"),
    skill!("diagram-maker"),
    skill!("eightctl"),
    skill!("gemini"),
    skill!("gh-issues"),
    skill!("gifgrep"),
    skill!("github"),
    skill!("gog"),
    skill!("goplaces"),
    skill!("healthcheck"),
    skill!("himalaya"),
    skill!("mcporter"),
    skill!("meme-maker"),
    skill!("model-usage"),
    skill!("nano-pdf"),
    skill!("node-connect"),
    skill!("node-inspect-debugger"),
    skill!("notion"),
    skill!("obsidian"),
    skill!("openai-whisper"),
    skill!("openai-whisper-api"),
    skill!("openhue"),
    skill!("oracle"),
    skill!("ordercli"),
    skill!("peekaboo"),
    skill!("python-debugpy"),
    skill!("sag"),
    skill!("session-logs"),
    skill!("sherpa-onnx-tts"),
    skill!("skill-creator", "Apache-2.0"),
    skill!("songsee"),
    skill!("sonoscli"),
    skill!("spike"),
    skill!("spotify-player"),
    skill!("summarize"),
    skill!("taskflow"),
    skill!("taskflow-inbox-triage"),
    skill!("things-mac"),
    skill!("tmux"),
    skill!("trello"),
    skill!("video-frames"),
    skill!("weather"),
    skill!("xurl"),
];

/// Returns all 51 official bundled skill descriptors.
#[must_use]
pub const fn registry() -> &'static [SkillDescriptor] {
    &REGISTRY
}

/// Looks up one bundled skill by exact identifier.
#[must_use]
pub fn descriptor(id: &str) -> Option<&'static SkillDescriptor> {
    REGISTRY.iter().find(|entry| entry.id == id)
}
