//! 120Hz analytic damped-spring physics engine and color interpolation primitives.
//!
//! Built directly on GPUI's closed-form harmonic oscillator (`gpui::SpringConfig`,
//! `gpui::SpringState`), ensuring frame-rate independence across 60Hz–240Hz displays,
//! velocity preservation across mid-flight interruptions, automatic Windows
//! Reduce Motion compliance, and zero idle CPU once settled.

use gpui::{App, Bounds, Pixels, Rgba, SpringConfig, SpringState, Styled as _};
use std::time::Instant;

/// Upper bound on a single integration step (22ms) so OS stalls never cause violent multi-frame jumps.
const MAX_STEP_DT: f32 = 0.022;

/// Upper bound on the very first integration step right after launching a page transition (12ms),
/// preventing Frame-0 cold DirectWrite text shaping / glyph atlas warm-up from teleporting Frame 1.
const MAX_FIRST_STEP_DT: f32 = 0.012;

/// Minimum choreographed settle horizon so pure horizontal rail glide + GPU per-card symmetric unfold finish crisply.
const CHOREO_SETTLE_S: f32 = 0.42;

/// Default settling tolerance for normalized `[0, 1]` presence animations.
pub const DEFAULT_PRESENCE_EPSILON: f32 = 0.002;

/// Sub-pixel settling tolerance for pixel-space sliding indicator geometry.
pub const SLIDING_INDICATOR_EPSILON_PX: f32 = 0.15;

/// Crisp, tactile spring for toggle switches, press feedback, and chip selection.
pub const SPRING_SNAPPY: SpringConfig = SpringConfig::new(540.0, 35.0, 1.0);

/// Fluid glass-pill spring for Dock, SubTab, and Segmented sliding indicators
/// (critically damped Liquid Glass capsule synced cleanly to the 280ms horizontal page rail).
pub const SPRING_PILL: SpringConfig = SpringConfig::new(380.0, 39.0, 1.0);

/// Strictly critically-damped Apple ProMotion silk deceleration spring (zero bounce, zero wobble).
pub const SPRING_PAGE: SpringConfig = SpringConfig::new(340.0, 36.9, 1.0);

/// Velvety jewel-like bloom spring (~2% organic settle) for inner icons & card items.
pub const SPRING_UNFOLD: SpringConfig = SpringConfig::new(240.0, 25.5, 1.0);

/// Crisp tactile GPU scale bloom spring for the active Dock icon (`k = 420, c = 22, m = 1`).
pub const SPRING_DOCK_ICON: SpringConfig = SpringConfig::new(420.0, 22.0, 1.0);

/// Expressive organic spring for Dynamic-Island toasts, modals, popovers, and HUD entry/exit.
pub const SPRING_SHEET: SpringConfig = SpringConfig::new(360.0, 31.0, 1.0);

/// Calm near-critically-damped spring for Hero card surface cross-fades and theme transitions.
pub const SPRING_GENTLE: SpringConfig = SpringConfig::new(220.0, 29.0, 1.0);

/// Razor-responsive spring for 48-bar timeline hover waves and card micro-elevation.
pub const SPRING_HOVER: SpringConfig = SpringConfig::new(620.0, 45.0, 1.0);

/// Snappy spring preset (`k = 540, c = 35, m = 1`) for toggles, presses, and chips.
pub const fn spring_snappy() -> SpringConfig {
    SPRING_SNAPPY
}

/// Sliding pill spring preset for Dock, SubTab, and Segmented Liquid Glass capsules.
pub const fn spring_pill() -> SpringConfig {
    SPRING_PILL
}

/// Critically-damped Apple ProMotion silk page emergence spring preset (`k = 290, c = 34.5, m = 1`).
pub const fn spring_page() -> SpringConfig {
    SPRING_PAGE
}

/// Velvety icon & content bloom spring preset (`k = 240, c = 25.5, m = 1`).
pub const fn spring_unfold() -> SpringConfig {
    SPRING_UNFOLD
}

/// Crisp Dock active icon scale-bloom spring preset (`k = 420, c = 22, m = 1`).
pub const fn spring_dock_icon() -> SpringConfig {
    SPRING_DOCK_ICON
}

/// Sheet/overlay spring preset (`k = 360, c = 31, m = 1`) for toasts, modals, popovers, and HUD.
pub const fn spring_sheet() -> SpringConfig {
    SPRING_SHEET
}

/// Gentle cross-fade spring preset (`k = 220, c = 29, m = 1`) for Hero cards and theme blends.
pub const fn spring_gentle() -> SpringConfig {
    SPRING_GENTLE
}

/// Hover spring preset (`k = 620, c = 45, m = 1`) for timeline hover waves and card lift.
pub const fn spring_hover() -> SpringConfig {
    SPRING_HOVER
}

/// Smooth cubic ease-out (`1 - (1 - t)^3`) clamped to `[0, 1]`.
#[inline]
pub fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    let inv = 1.0 - t;
    1.0 - inv * inv * inv
}

/// Smooth quartic ease-out (`1 - (1 - t)^4`) clamped to `[0, 1]`.
#[inline]
pub fn ease_out_quart(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    let inv = 1.0 - t;
    let inv2 = inv * inv;
    1.0 - inv2 * inv2
}

/// Signature Apple ProMotion butter-smooth quintic deceleration (`1 - (1 - t)^5`) with zero bounce.
#[inline]
pub fn ease_out_quint(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    let inv = 1.0 - t;
    let inv2 = inv * inv;
    1.0 - inv2 * inv2 * inv
}

/// Normalized critically-damped harmonic oscillator (`ζ = 1.0`, zero bounce, zero Frame-1 jerk,
/// zero dead-tail 1px crawl) arriving cleanly at `1.0` at `t == duration_s`.
///
/// Matches Apple ProMotion `CASpringAnimation` S-curve kinematics: starts smoothly from zero
/// velocity, accelerates briskly to peak velocity around `t = 1 / omega`, then settles effortlessly.
#[inline]
pub fn spring_crit_damped(t: f32, duration_s: f32, omega: f32) -> f32 {
    if t <= 0.0 || duration_s <= 0.0 {
        return 0.0;
    }
    if t >= duration_s {
        return 1.0;
    }
    let raw = 1.0 - (1.0 + omega * t) * (-omega * t).exp();
    let end = 1.0 - (1.0 + omega * duration_s) * (-omega * duration_s).exp();
    if end <= f32::EPSILON {
        1.0
    } else {
        (raw / end).clamp(0.0, 1.0)
    }
}

/// Ultra-subtle organic back-out (`c1 = 0.72`) for jewel-like icon scale bloom without harsh bounce.
#[inline]
pub fn ease_out_back_soft(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    const C1: f32 = 0.72;
    const C3: f32 = C1 + 1.0;
    let x = t - 1.0;
    1.0 + C3 * x * x * x + C1 * x * x
}

/// Closed-form analytic spring evaluation safe at `dt <= 0.0` and arbitrary positive `dt`.
#[inline]
fn step_exact(cfg: SpringConfig, state: SpringState, target: f32, dt: f32) -> SpringState {
    if dt <= 0.0 {
        state
    } else {
        cfg.step(state, target, dt)
    }
}

/// One-dimensional stateful analytic damped spring with automatic idle deactivation.
#[derive(Clone, Debug)]
pub struct SpringSlot {
    state: SpringState,
    target: f32,
    last_tick: Option<Instant>,
    active: bool,
}

impl Default for SpringSlot {
    fn default() -> Self {
        Self::new(0.0)
    }
}

impl SpringSlot {
    /// Creates a settled spring initialized at `initial` with zero velocity.
    pub fn new(initial: f32) -> Self {
        Self {
            state: SpringState {
                position: initial,
                velocity: 0.0,
            },
            target: initial,
            last_tick: None,
            active: false,
        }
    }

    /// Current instantaneous position of the spring.
    pub fn value(&self) -> f32 {
        self.state.position
    }

    /// Current instantaneous velocity of the spring (units per second).
    pub fn velocity(&self) -> f32 {
        self.state.velocity
    }

    /// Current target position of the spring.
    pub fn target(&self) -> f32 {
        self.target
    }

    /// Whether the spring still needs animation frames to settle.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Immediately jumps to `value`, zeroing velocity and deactivating animation frames.
    pub fn snap(&mut self, value: f32) {
        self.state = SpringState {
            position: value,
            velocity: 0.0,
        };
        self.target = value;
        self.last_tick = None;
        self.active = false;
    }

    /// Launches a fresh spring trajectory from `start` with initial `initial_velocity` toward `target`.
    pub fn launch(&mut self, start: f32, target: f32, initial_velocity: f32, reduce_motion: bool) {
        if reduce_motion {
            self.snap(target);
            return;
        }
        self.state = SpringState {
            position: start,
            velocity: initial_velocity,
        };
        self.target = target;
        self.last_tick = None;
        self.active = true;
    }

    /// Retargets the spring while preserving instantaneous position and velocity.
    ///
    /// When `reduce_motion` is `true`, snaps immediately to `target`.
    pub fn set_target(&mut self, target: f32, reduce_motion: bool) {
        if reduce_motion {
            self.snap(target);
            return;
        }
        self.target = target;
        if !self.active {
            if (self.state.position - target).abs() <= f32::EPSILON && self.state.velocity == 0.0 {
                return;
            }
            self.last_tick = None;
            self.active = true;
        }
    }

    /// Advances the spring to `now` using `cfg`.
    ///
    /// Clamps per-frame `dt <= 0.05s`, snaps cleanly to `target` once settled within `eps`,
    /// and returns `true` while further animation frames are required (`false` at idle rest).
    pub fn tick(&mut self, now: Instant, cfg: SpringConfig, eps: f32) -> bool {
        if !self.active {
            return false;
        }
        let dt = match self.last_tick {
            Some(prev) => now
                .saturating_duration_since(prev)
                .as_secs_f32()
                .min(MAX_STEP_DT),
            None => 0.0,
        };
        self.last_tick = Some(now);

        if dt > 0.0 {
            self.state = cfg.step(self.state, self.target, dt);
        }

        if cfg.is_settled(self.state, self.target, eps) {
            self.state = SpringState {
                position: self.target,
                velocity: 0.0,
            };
            self.active = false;
            self.last_tick = None;
            false
        } else {
            true
        }
    }
}

/// Enter + Exit mount lifecycle controller driven by a normalized `[0, 1]` spring.
///
/// Keeps overlays, modals, popovers, and toasts mounted while animating out, then
/// reports `is_mounted() == false` once settled at `0.0` so idle cost drops to zero.
#[derive(Clone, Debug)]
pub struct PresenceSpring {
    want_open: bool,
    slot: SpringSlot,
}

impl Default for PresenceSpring {
    fn default() -> Self {
        Self::new(false)
    }
}

impl PresenceSpring {
    /// Creates a presence spring initially open (`1.0`) or closed (`0.0`).
    pub fn new(open: bool) -> Self {
        Self {
            want_open: open,
            slot: SpringSlot::new(if open { 1.0 } else { 0.0 }),
        }
    }

    /// Transitions the desired visibility state, preserving spring momentum if interrupted.
    pub fn set_open(&mut self, open: bool, reduce_motion: bool) {
        self.want_open = open;
        self.slot
            .set_target(if open { 1.0 } else { 0.0 }, reduce_motion);
    }

    /// Advances the presence spring to `now`, returning `true` while more frames are needed.
    pub fn tick(&mut self, now: Instant, cfg: SpringConfig) -> bool {
        self.slot.tick(now, cfg, DEFAULT_PRESENCE_EPSILON)
    }

    /// Clamped `[0.0, 1.0]` progress safe for opacity, scrim alpha, and color blends.
    pub fn progress(&self) -> f32 {
        self.slot.value().clamp(0.0, 1.0)
    }

    /// Unclamped spring progress permitting subtle physical overshoot on sheet/toast transforms.
    pub fn raw_progress(&self) -> f32 {
        self.slot.value()
    }

    /// Whether the element should remain mounted in the UI tree (open or still animating out).
    pub fn is_mounted(&self) -> bool {
        self.want_open || self.slot.is_active() || self.slot.value() > DEFAULT_PRESENCE_EPSILON
    }

    /// Whether the logical target state is open.
    pub fn is_open(&self) -> bool {
        self.want_open
    }

    /// Whether the underlying spring is actively ticking.
    pub fn is_active(&self) -> bool {
        self.slot.is_active()
    }
}

/// Coupled `(x, width)` spring tracker for sliding glass indicators in Dock, SubTabs,
/// and Segmented controls.
#[derive(Clone, Debug, Default)]
pub struct SlidingIndicatorState {
    x: SpringSlot,
    width: SpringSlot,
    initialized: bool,
    rects: Vec<(f32, f32)>,
}

impl SlidingIndicatorState {
    /// Creates an uninitialized sliding indicator awaiting its first layout pass.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records measured child bounds relative to `container_left` and targets `active_idx`.
    ///
    /// On the first layout pass, snaps immediately to `active_idx` so indicators never fly
    /// in from `x = 0` on initial mount.
    pub fn record_bounds(
        &mut self,
        container_left: f32,
        child_bounds: &[Bounds<Pixels>],
        active_idx: usize,
        reduce_motion: bool,
    ) {
        self.rects.clear();
        self.rects.extend(
            child_bounds
                .iter()
                .map(|b| (b.left().as_f32() - container_left, b.size.width.as_f32())),
        );

        let Some(&(target_x, target_w)) = self.rects.get(active_idx) else {
            return;
        };

        if !self.initialized {
            self.x.snap(target_x);
            self.width.snap(target_w);
            self.initialized = true;
        } else {
            self.x.set_target(target_x, reduce_motion);
            self.width.set_target(target_w, reduce_motion);
        }
    }

    /// Retargets the indicator to `active_idx` using previously measured child rects.
    pub fn select(&mut self, active_idx: usize, reduce_motion: bool) {
        let Some(&(target_x, target_w)) = self.rects.get(active_idx) else {
            return;
        };
        if !self.initialized {
            self.x.snap(target_x);
            self.width.snap(target_w);
            self.initialized = true;
        } else {
            self.x.set_target(target_x, reduce_motion);
            self.width.set_target(target_w, reduce_motion);
        }
    }

    /// Advances both `x` and `width` springs using [`spring_pill()`].
    ///
    /// Returns `true` while either axis still needs animation frames.
    pub fn tick(&mut self, now: Instant) -> bool {
        let cfg = spring_pill();
        let active_x = self.x.tick(now, cfg, SLIDING_INDICATOR_EPSILON_PX);
        let active_w = self.width.tick(now, cfg, SLIDING_INDICATOR_EPSILON_PX);
        active_x || active_w
    }

    /// Returns the current `(left_px, width_px)` relative to the container, if initialized.
    pub fn geometry(&self) -> Option<(f32, f32)> {
        self.initialized
            .then(|| (self.x.value(), self.width.value().max(0.0)))
    }

    /// Velocity-coupled Liquid Glass horizontal elongation (`0..=9px`) during capsule flight.
    pub fn stretch_px(&self) -> f32 {
        (self.x.velocity().abs() * 0.0065).min(9.0)
    }

    /// Returns Liquid Glass `(left_px, width_px)` with symmetric velocity-coupled stretch.
    pub fn liquid_geometry(&self) -> Option<(f32, f32)> {
        self.geometry().map(|(x, w)| {
            let stretch = self.stretch_px();
            ((x - stretch * 0.5).max(0.0), (w + stretch).max(0.0))
        })
    }

    /// Whether either `x` or `width` spring is still animating.
    pub fn is_active(&self) -> bool {
        self.x.is_active() || self.width.is_active()
    }
}

/// Per-card spatial choreography pose (`dx`, `dy`, `opacity`, `scale`, `inset_px`, `shadow_alpha`)
/// produced by [`PageChoreo`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SlotPose {
    pub dx: f32,
    pub dy: f32,
    pub opacity: f32,
    /// `0.76..=1.03` scale factor for icon bloom inside fixed tiles.
    pub scale: f32,
    /// Symmetric in-place shell contraction inset (`8.5 -> 0.0 px`) for zero-reflow card unfolding.
    pub inset_px: f32,
    /// Card elevation shadow bloom alpha (`0.0 -> 1.0`).
    pub shadow_alpha: f32,
}

impl Default for SlotPose {
    fn default() -> Self {
        Self::SETTLED
    }
}

impl SlotPose {
    /// Identity pose at visual rest
    /// (`dx = 0`, `dy = 0`, `opacity = 1`, `scale = 1`, `inset_px = 0`, `shadow_alpha = 1`).
    pub const SETTLED: Self = Self {
        dx: 0.0,
        dy: 0.0,
        opacity: 1.0,
        scale: 1.0,
        inset_px: 0.0,
        shadow_alpha: 1.0,
    };

    /// Returns `true` when visually settled at rest
    /// (`|dx| < 0.05`, `|dy| < 0.05`, `opacity >= 0.995`, `|scale - 1.0| < 0.004`,
    /// `inset_px < 0.04`, `shadow_alpha >= 0.995`).
    pub fn is_settled(self) -> bool {
        self.dx.abs() < 0.05
            && self.dy.abs() < 0.05
            && self.opacity >= 0.995
            && (self.scale - 1.0).abs() < 0.004
            && self.inset_px < 0.04
            && self.shadow_alpha >= 0.995
    }

    /// Applies spatial offset and opacity to `el`, returning `el` untouched once settled.
    ///
    /// When `dx == 0` and `dy == 0`, applies only `.opacity(self.opacity)` cleanly without
    /// wrapping `el` in unnecessary `.relative().left().top()` positioning styles.
    pub fn apply(self, el: gpui::Div) -> gpui::Div {
        if self.is_settled() {
            el
        } else if self.dx.abs() < 0.05 && self.dy.abs() < 0.05 {
            if self.opacity >= 0.995 {
                el
            } else {
                el.opacity(self.opacity)
            }
        } else {
            el.relative()
                .left(gpui::px(self.dx))
                .top(gpui::px(self.dy))
                .opacity(self.opacity)
        }
    }
}

/// 120Hz "Pure Horizontal Rail Glide + Symmetric In-Place Per-Card Unfold" choreography evaluator.
///
/// Horizontal translation happens ONCE on the outer incoming pane (`DirectionalTransition::page_rail_dx`),
/// while every card and inner element inside strictly preserves `dx == 0.0` AND `dy == 0.0` ALWAYS
/// (zero diagonal fly-in, zero vertical drift, zero sideways wobble). Instead, each card sequentially
/// unfolds outward symmetrically from its own center (`inset_px: 8.5 -> 0.0 px` on [`ease_out_quint`],
/// `shadow_alpha: 0.0 -> 1.0`), and inner brand icons bloom gracefully (`0.76 -> 1.0` via [`ease_out_back_soft`]).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PageChoreo {
    pub elapsed_s: f32,
    pub direction: i8,
    pub active: bool,
}

impl Default for PageChoreo {
    fn default() -> Self {
        Self::settled()
    }
}

impl PageChoreo {
    /// Settled choreography where every slot evaluates to [`SlotPose::SETTLED`].
    pub const fn settled() -> Self {
        Self {
            elapsed_s: 2.0,
            direction: 1,
            active: false,
        }
    }

    /// Evaluates the pose for a primary vertical section (`tier = 0, 1, 2, ...`).
    pub fn slot(self, tier: usize) -> SlotPose {
        self.tile(tier, 0)
    }

    /// Evaluates the Pure In-Place Symmetric GPU Per-Card Unfold pose for a Bento card at `(tier, sub_idx)`.
    ///
    /// - `dx == 0.0` AND `dy == 0.0` STRICTLY ALWAYS (zero diagonal motion, zero card wobble).
    /// - Musical sequential ripple (`card_seq = (tier * 2 + sub_idx).min(5)`, `24ms` stagger, max `120ms`):
    ///   each card's GPU ceramic shell unfolds symmetrically outward from `inset_px = 11.0 -> 0.0 px`
    ///   over `280ms` on a critically-damped Apple ProMotion spring (`ω = 19.5`, zero dead-tail 1px crawl),
    ///   while elevation shadow blooms `0.0 -> 1.0` and content unveils smoothly (`0.30 -> 1.0`).
    pub fn tile(self, tier: usize, sub_idx: usize) -> SlotPose {
        if !self.active {
            return SlotPose::SETTLED;
        }

        let card_seq = tier.saturating_mul(2).saturating_add(sub_idx).min(5) as f32;
        let delay_s = (card_seq * 0.024).min(0.12);
        let local_t = (self.elapsed_s - delay_s).max(0.0);
        let p = spring_crit_damped(local_t, 0.28, 19.5);
        let inset_px = (1.0 - p) * 11.0;
        let shadow_alpha = ease_out_cubic((local_t / 0.22).clamp(0.0, 1.0));
        let opacity = (0.30
            + 0.70
                * ease_out_cubic(
                    ((self.elapsed_s - delay_s * 0.45).max(0.0) / 0.15).clamp(0.0, 1.0),
                ))
        .clamp(0.0, 1.0);

        SlotPose {
            dx: 0.0,
            dy: 0.0,
            opacity,
            scale: 1.0,
            inset_px,
            shadow_alpha,
        }
    }

    /// Evaluates the zero-reflow in-place unveil pose for nested Launch Pads and inner tiles (`parent_tier`).
    ///
    /// Keeps `dx == 0.0`, `dy == 0.0`, and `scale == 1.0` (zero layout-stepping icon jitter),
    /// providing a velvety staggered GPU opacity & micro-shell unveil.
    pub fn inner_bloom(self, parent_tier: usize, sub_idx: usize) -> SlotPose {
        if !self.active {
            return SlotPose::SETTLED;
        }

        let delay_s =
            (0.045 + parent_tier.min(3) as f32 * 0.032 + sub_idx.min(4) as f32 * 0.022).min(0.18);
        let local_t = (self.elapsed_s - delay_s).max(0.0);
        let p = spring_crit_damped(local_t, 0.22, 20.0);
        let inset_px = (1.0 - p) * 3.0;
        let shadow_alpha = ease_out_cubic((local_t / 0.18).clamp(0.0, 1.0));
        let opacity = if self.elapsed_s <= delay_s {
            0.28
        } else {
            (0.28 + 0.72 * ease_out_cubic((local_t / 0.16).clamp(0.0, 1.0))).clamp(0.0, 1.0)
        };

        SlotPose {
            dx: 0.0,
            dy: 0.0,
            opacity,
            scale: 1.0,
            inset_px,
            shadow_alpha,
        }
    }

    /// Returns fixed `1.0` icon scale to keep raster brand tiles razor-sharp with zero layout stepping.
    pub fn icon_scale(self, _parent_tier: usize, _sub_idx: usize) -> f32 {
        1.0
    }
}

/// Pure horizontal spatial transition controller for main pages and sub-tab views.
///
/// Drives a single zero-layout-cost GPU horizontal rail (`page_rail_dx`, strictly `dy == 0.0`)
/// on a critically-damped Apple ProMotion spring (`280ms`, zero Frame-0 clock-poisoning jump,
/// zero dead-tail 1px crawl) paired with sequential GPU per-card symmetric unfold ([`PageChoreo`]),
/// automatically idling at zero CPU once settled at `420ms`.
#[derive(Clone, Debug)]
pub struct DirectionalTransition<K: Copy + Eq> {
    active: K,
    exiting: Option<K>,
    direction: i8,
    progress: SpringSlot,
    elapsed_s: f32,
    frames_advanced: u32,
    last_tick: Option<Instant>,
    running: bool,
}

impl<K: Copy + Eq> DirectionalTransition<K> {
    /// Creates a settled transition controller initialized at `initial`.
    pub fn new(initial: K) -> Self {
        Self {
            active: initial,
            exiting: None,
            direction: 1,
            progress: SpringSlot::new(1.0),
            elapsed_s: 2.0,
            frames_advanced: 0,
            last_tick: None,
            running: false,
        }
    }

    /// Transitions to `next` along `direction` (`>= 0` forward/right, `< 0` backward/left).
    ///
    /// Interruptible mid-flight: rapidly switching tabs immediately starts a fresh spatial
    /// transition from the current screen without visual glitches or deadlocks.
    pub fn transition_to(&mut self, next: K, direction: i8, reduce_motion: bool) {
        if next == self.active {
            return;
        }
        let dir = if direction >= 0 { 1 } else { -1 };
        if reduce_motion {
            self.active = next;
            self.exiting = None;
            self.direction = dir;
            self.progress.snap(1.0);
            self.elapsed_s = 2.0;
            self.frames_advanced = 0;
            self.last_tick = None;
            self.running = false;
            return;
        }
        self.exiting = Some(self.active);
        self.active = next;
        self.direction = dir;
        self.progress.launch(0.0, 1.0, 0.0, false);
        self.elapsed_s = 0.0;
        self.frames_advanced = 0;
        self.last_tick = None;
        self.running = true;
    }

    /// Advances the spatial transition spring and choreography clock to `now`.
    ///
    /// Guards against Frame-0 clock poisoning: the first post-launch integration step is capped at
    /// `MAX_FIRST_STEP_DT` (`12ms`) so cold view/glyph build work on Frame 0 never teleports Frame 1.
    pub fn tick(&mut self, now: Instant) -> bool {
        if !self.running {
            return false;
        }
        let dt = match self.last_tick {
            Some(prev) => {
                let cap = if self.frames_advanced == 0 {
                    MAX_FIRST_STEP_DT
                } else {
                    MAX_STEP_DT
                };
                self.frames_advanced = self.frames_advanced.saturating_add(1);
                now.saturating_duration_since(prev).as_secs_f32().min(cap)
            }
            None => 0.0,
        };
        self.last_tick = Some(now);
        self.elapsed_s += dt;

        let progress_active = self
            .progress
            .tick(now, spring_page(), DEFAULT_PRESENCE_EPSILON);

        if self.elapsed_s >= 0.10 {
            self.exiting = None;
        }

        if self.elapsed_s >= CHOREO_SETTLE_S && (!progress_active || self.elapsed_s >= 0.50) {
            self.exiting = None;
            self.last_tick = None;
            self.frames_advanced = 0;
            self.progress.snap(1.0);
            self.running = false;
            false
        } else {
            true
        }
    }

    /// Whether the spatial transition or staggered choreography still needs animation frames.
    pub fn is_active(&self) -> bool {
        self.running
    }

    /// Currently active view key.
    pub fn active(&self) -> K {
        self.active
    }

    /// Snapshot of the Pure Horizontal Rail + Symmetric GPU Per-Card Unfold choreography evaluator.
    pub fn choreo(&self) -> PageChoreo {
        PageChoreo {
            elapsed_s: self.elapsed_s,
            direction: self.direction,
            active: self.is_active(),
        }
    }

    /// Pure horizontal rail offset (px) applied ONCE to the single outer incoming page via `OffsetPane`.
    ///
    /// Glides smoothly from `direction * travel_px -> 0.0` over `280ms` on a normalized
    /// critically-damped Apple ProMotion spring (`ω = 21.0 rad/s`, zero bounce, zero Frame-1 jump,
    /// zero dead-tail 1px crawl) with strictly zero vertical drift.
    pub fn page_rail_dx(&self, travel_px: f32) -> f32 {
        if !self.is_active() {
            return 0.0;
        }
        let p = spring_crit_damped(self.elapsed_s, 0.28, 21.0);
        if p >= 1.0 {
            0.0
        } else {
            (self.direction as f32) * (1.0 - p) * travel_px
        }
    }

    /// Fast, crisp incoming pane opacity unveil (`0.48 -> 1.0` over `95ms`) synced to `page_rail_dx`.
    pub fn page_opacity(&self) -> f32 {
        if !self.is_active() {
            return 1.0;
        }
        (0.48 + 0.52 * ease_out_cubic((self.elapsed_s / 0.095).clamp(0.0, 1.0))).clamp(0.0, 1.0)
    }

    /// Crisp tactile GPU scale bloom (`0.82 -> ~1.04 -> 1.0`) for the newly active Dock tab icon.
    pub fn active_icon_bloom_scale(&self) -> f32 {
        if !self.is_active() {
            return 1.0;
        }
        step_exact(
            SPRING_DOCK_ICON,
            SpringState {
                position: 0.82,
                velocity: 3.4,
            },
            1.0,
            self.elapsed_s,
        )
        .position
        .clamp(0.80, 1.08)
    }

    /// Gentle Dock active icon vertical micro-lift (`-1.4px` peak lift, settling cleanly to `0.0`).
    pub fn active_icon_bloom_dy(&self) -> f32 {
        if !self.is_active() {
            return 0.0;
        }
        // Closed-form velocity impulse of SPRING_DOCK_ICON (analytic peak ~10.815 at t ≈ 58.1ms)
        let vel = step_exact(
            SPRING_DOCK_ICON,
            SpringState {
                position: 0.0,
                velocity: 0.0,
            },
            1.0,
            self.elapsed_s,
        )
        .velocity;
        let normalized = (vel / 10.815).clamp(-0.22, 1.0);
        -1.4 * normalized
    }

    /// Fast-rise opacity curve for the entering view (legible within ~55ms).
    pub fn entering_opacity(&self) -> f32 {
        (self.progress.value() * 1.45).clamp(0.0, 1.0)
    }

    /// Horizontal glide offset (px) for the entering view (`+travel -> 0` or `-travel -> 0`).
    pub fn entering_offset_x(&self, travel_px: f32) -> f32 {
        let remain = (1.0 - self.progress.value()).clamp(-0.15, 1.0);
        self.direction as f32 * remain * travel_px
    }

    /// Subtle vertical micro-lift (px) accompanying the entering glide.
    pub fn entering_offset_y(&self, lift_px: f32) -> f32 {
        ((1.0 - self.progress.value()) * lift_px).max(0.0)
    }

    /// Returns `(exiting_key, opacity, offset_x_px)` while the outgoing ghost layer is visible.
    ///
    /// Glides cleanly away (`0 -> -direction * exit_travel_px`) and dissolves over 130ms via
    /// [`ease_out_cubic`], clearing cleanly once `elapsed_s >= 0.135` or `opacity <= 0.01`.
    pub fn exiting_layer(&self, exit_travel_px: f32) -> Option<(K, f32, f32)> {
        if self.elapsed_s >= 0.135 {
            return None;
        }
        let key = self.exiting?;
        let u = (self.elapsed_s / 0.13).clamp(0.0, 1.0);
        let eased = ease_out_cubic(u);
        let opacity = (1.0 - eased).clamp(0.0, 1.0);
        if opacity <= 0.01 {
            return None;
        }
        let offset_x = if exit_travel_px == 0.0 || eased == 0.0 {
            0.0
        } else {
            -(self.direction as f32) * eased * exit_travel_px
        };
        Some((key, opacity, offset_x))
    }
}

/// Synchronizes GPUI's global `reduce_motion` state with the Windows OS accessibility setting.
pub fn sync_windows_reduce_motion(cx: &mut App) {
    let reduce = crate::tray_win::query_windows_reduce_motion();
    cx.set_reduce_motion(reduce);
}

/// Linearly interpolates between two `0xRRGGBB` colors at clamped `t` in `[0.0, 1.0]`.
pub fn lerp_rgb(a: u32, b: u32, t: f32) -> Rgba {
    let t = t.clamp(0.0, 1.0);
    let ar = ((a >> 16) & 0xFF) as f32 / 255.0;
    let ag = ((a >> 8) & 0xFF) as f32 / 255.0;
    let ab = (a & 0xFF) as f32 / 255.0;

    let br = ((b >> 16) & 0xFF) as f32 / 255.0;
    let bg = ((b >> 8) & 0xFF) as f32 / 255.0;
    let bb = (b & 0xFF) as f32 / 255.0;

    Rgba {
        r: ar + (br - ar) * t,
        g: ag + (bg - ag) * t,
        b: ab + (bb - ab) * t,
        a: 1.0,
    }
}

/// Linearly interpolates between two `0xRRGGBBAA` colors at clamped `t` in `[0.0, 1.0]`.
pub fn lerp_rgba(a: u32, b: u32, t: f32) -> Rgba {
    let t = t.clamp(0.0, 1.0);
    let ar = ((a >> 24) & 0xFF) as f32 / 255.0;
    let ag = ((a >> 16) & 0xFF) as f32 / 255.0;
    let ab = ((a >> 8) & 0xFF) as f32 / 255.0;
    let aa = (a & 0xFF) as f32 / 255.0;

    let br = ((b >> 24) & 0xFF) as f32 / 255.0;
    let bg = ((b >> 16) & 0xFF) as f32 / 255.0;
    let bb = ((b >> 8) & 0xFF) as f32 / 255.0;
    let ba = (b & 0xFF) as f32 / 255.0;

    Rgba {
        r: ar + (br - ar) * t,
        g: ag + (bg - ag) * t,
        b: ab + (bb - ab) * t,
        a: aa + (ba - aa) * t,
    }
}

/// Scales the alpha channel of a `0xRRGGBBAA` color by clamped `scale` in `[0.0, 1.0]`.
pub fn rgba_with_alpha_scale(hex_rgba: u32, scale: f32) -> Rgba {
    let s = scale.clamp(0.0, 1.0);
    let r = ((hex_rgba >> 24) & 0xFF) as f32 / 255.0;
    let g = ((hex_rgba >> 16) & 0xFF) as f32 / 255.0;
    let b = ((hex_rgba >> 8) & 0xFF) as f32 / 255.0;
    let a = ((hex_rgba & 0xFF) as f32 / 255.0) * s;
    Rgba { r, g, b, a }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{point, px, size};
    use std::time::Duration;

    #[test]
    fn all_spring_presets_converge_and_deactivate_at_idle() {
        let presets = [
            spring_snappy(),
            spring_pill(),
            spring_page(),
            spring_unfold(),
            spring_dock_icon(),
            spring_sheet(),
            spring_gentle(),
            spring_hover(),
        ];

        for cfg in presets {
            let mut slot = SpringSlot::new(0.0);
            assert!(!slot.is_active());
            slot.set_target(1.0, false);
            assert!(slot.is_active());

            let start = Instant::now();
            let mut now = start;
            let mut frames = 0usize;
            while slot.tick(now, cfg, 0.001) {
                now += Duration::from_micros(8_333); // 120Hz cadence
                frames += 1;
                assert!(
                    frames < 400,
                    "spring failed to settle within 400 120Hz frames: {slot:?}"
                );
            }

            assert!(!slot.is_active());
            assert_eq!(slot.value(), 1.0);
            assert_eq!(slot.velocity(), 0.0);
            assert!(
                frames > 5,
                "expected smooth multi-frame motion, got {frames}"
            );
        }
    }

    #[test]
    fn spring_retarget_mid_flight_preserves_velocity_without_teleporting() {
        let cfg = spring_snappy();
        let mut slot = SpringSlot::new(0.0);
        slot.set_target(100.0, false);

        let t0 = Instant::now();
        assert!(slot.tick(t0, cfg, 0.01));
        assert!(slot.tick(t0 + Duration::from_millis(30), cfg, 0.01));
        let mid_pos = slot.value();
        let mid_vel = slot.velocity();
        assert!(mid_pos > 10.0 && mid_pos < 95.0);
        assert!(mid_vel > 100.0);

        // Retarget back to 0.0 mid-flight: position and velocity must stay continuous.
        slot.set_target(0.0, false);
        assert_eq!(slot.value(), mid_pos);
        assert_eq!(slot.velocity(), mid_vel);
        assert!(slot.is_active());

        // Over the next 8ms, positive momentum carries briefly upward before pulling back.
        assert!(slot.tick(t0 + Duration::from_millis(38), cfg, 0.01));
        assert!((slot.value() - mid_pos).abs() < 25.0);

        // Eventually converges smoothly to 0.0.
        let mut now = t0 + Duration::from_millis(46);
        let mut steps = 0;
        while slot.tick(now, cfg, 0.01) {
            now += Duration::from_millis(8);
            steps += 1;
            assert!(steps < 300);
        }
        assert_eq!(slot.value(), 0.0);
        assert!(!slot.is_active());
    }

    #[test]
    fn spring_tick_clamps_stall_dt_and_reduce_motion_snaps_immediately() {
        let cfg = spring_sheet();
        let mut stalled = SpringSlot::new(0.0);
        stalled.set_target(1.0, false);
        let t0 = Instant::now();
        stalled.tick(t0, cfg, 0.001);
        // Simulate a 5-second OS stall; dt must be clamped to 0.05s rather than instant jump.
        let still_running = stalled.tick(t0 + Duration::from_secs(5), cfg, 0.001);
        assert!(still_running);
        assert!(
            stalled.value() < 0.85,
            "expected clamped 50ms step, got {}",
            stalled.value()
        );

        // Reduce motion snaps immediately with zero active frames.
        let mut reduced = SpringSlot::new(0.0);
        reduced.set_target(42.0, true);
        assert!(!reduced.is_active());
        assert_eq!(reduced.value(), 42.0);
        assert_eq!(reduced.target(), 42.0);
        assert!(!reduced.tick(t0, cfg, 0.001));
    }

    #[test]
    fn presence_spring_manages_enter_exit_mount_lifecycle() {
        let cfg = spring_sheet();
        let mut presence = PresenceSpring::new(false);
        assert!(!presence.is_mounted());
        assert!(!presence.is_open());
        assert_eq!(presence.progress(), 0.0);

        // Enter
        presence.set_open(true, false);
        assert!(presence.is_mounted());
        assert!(presence.is_open());
        assert!(presence.is_active());

        let mut now = Instant::now();
        let mut saw_overshoot = false;
        while presence.tick(now, cfg) {
            if presence.raw_progress() > 1.0 {
                saw_overshoot = true;
                assert_eq!(presence.progress(), 1.0);
            }
            now += Duration::from_millis(8);
        }
        assert!(
            saw_overshoot,
            "spring_sheet should produce subtle physical overshoot"
        );
        assert!(presence.is_mounted());
        assert!(!presence.is_active());
        assert_eq!(presence.progress(), 1.0);

        // Exit stays mounted while animating down to 0
        presence.set_open(false, false);
        assert!(!presence.is_open());
        assert!(presence.is_mounted());
        assert!(presence.is_active());

        now += Duration::from_millis(8);
        assert!(presence.tick(now, cfg));
        assert!(presence.is_mounted());

        while presence.tick(now, cfg) {
            now += Duration::from_millis(8);
        }
        assert!(!presence.is_mounted());
        assert!(!presence.is_active());
        assert_eq!(presence.progress(), 0.0);

        // Reduce motion mounts/unmounts instantaneously
        presence.set_open(true, true);
        assert!(presence.is_mounted());
        assert!(!presence.is_active());
        assert_eq!(presence.progress(), 1.0);

        presence.set_open(false, true);
        assert!(!presence.is_mounted());
        assert!(!presence.is_active());
        assert_eq!(presence.progress(), 0.0);
    }

    #[test]
    fn sliding_indicator_snaps_on_first_layout_and_glides_on_selection() {
        let mut indicator = SlidingIndicatorState::new();
        assert_eq!(indicator.geometry(), None);

        let bounds = [
            Bounds::new(point(px(10.0), px(0.0)), size(px(60.0), px(28.0))),
            Bounds::new(point(px(74.0), px(0.0)), size(px(92.0), px(28.0))),
            Bounds::new(point(px(170.0), px(0.0)), size(px(50.0), px(28.0))),
        ];

        // First layout snaps directly to tab 1 relative to container_left = 10.0
        indicator.record_bounds(10.0, &bounds, 1, false);
        assert_eq!(indicator.geometry(), Some((64.0, 92.0)));
        assert!(!indicator.is_active());

        // Switching to tab 2 animates both x and width smoothly
        indicator.select(2, false);
        assert!(indicator.is_active());

        let mut now = Instant::now();
        let mut ticks = 0usize;
        while indicator.tick(now) {
            now += Duration::from_millis(8);
            ticks += 1;
            assert!(ticks < 300);
        }
        assert!(ticks > 5);
        assert!(!indicator.is_active());
        assert_eq!(indicator.geometry(), Some((160.0, 50.0)));

        // Reduce motion snaps straight to tab 0
        indicator.select(0, true);
        assert!(!indicator.is_active());
        assert_eq!(indicator.geometry(), Some((0.0, 60.0)));
    }

    #[test]
    fn color_interpolation_and_alpha_scaling_clamp_cleanly() {
        let start = lerp_rgb(0x000000, 0xFFFFFF, -0.5);
        assert_eq!(
            start,
            Rgba {
                r: 0.0,
                g: 0.0,
                b: 0.0,
                a: 1.0
            }
        );

        let end = lerp_rgb(0x000000, 0xFFFFFF, 1.5);
        assert_eq!(
            end,
            Rgba {
                r: 1.0,
                g: 1.0,
                b: 1.0,
                a: 1.0
            }
        );

        let mid = lerp_rgb(0x204080, 0x4080C0, 0.5);
        assert!((mid.r - 48.0 / 255.0).abs() < 1e-4);
        assert!((mid.g - 96.0 / 255.0).abs() < 1e-4);
        assert!((mid.b - 160.0 / 255.0).abs() < 1e-4);
        assert_eq!(mid.a, 1.0);

        let scaled = rgba_with_alpha_scale(0x2563EB80, 0.5);
        assert!((scaled.r - 0x25 as f32 / 255.0).abs() < 1e-4);
        assert!((scaled.g - 0x63 as f32 / 255.0).abs() < 1e-4);
        assert!((scaled.b - 0xEB as f32 / 255.0).abs() < 1e-4);
        assert!((scaled.a - (0x80 as f32 / 255.0) * 0.5).abs() < 1e-4);

        let rgba_mid = lerp_rgba(0x00000000, 0xFFFFFFFF, 0.25);
        assert!((rgba_mid.a - 0.25).abs() < 1e-4);
    }

    #[test]
    fn pure_easing_curves_satisfy_boundaries_and_monotonic_deceleration() {
        for f in [
            ease_out_cubic,
            ease_out_quart,
            ease_out_quint,
            ease_out_back_soft,
        ] {
            assert_eq!(f(-0.5), 0.0);
            assert_eq!(f(0.0), 0.0);
            assert!((f(1.0) - 1.0).abs() < 1e-6);
            assert!((f(1.5) - 1.0).abs() < 1e-6);
        }

        // Cubic, quartic, quintic ease-out are strictly monotonic with zero overshoot
        for f in [ease_out_cubic, ease_out_quart, ease_out_quint] {
            let mut prev = 0.0_f32;
            for step in 1..=100 {
                let t = step as f32 / 100.0;
                let v = f(t);
                assert!(
                    v >= prev && v <= 1.0,
                    "non-monotonic ease_out at t={t}: {v}"
                );
                prev = v;
            }
        }
        // Higher order ease-out leads earlier for interior t
        assert!(ease_out_quint(0.4) > ease_out_quart(0.4));
        assert!(ease_out_quart(0.4) > ease_out_cubic(0.4));

        // ease_out_back_soft has an ultra-subtle organic overshoot (> 1.0, < 1.03)
        let mut peak = 0.0_f32;
        for step in 0..=200 {
            let t = step as f32 / 200.0;
            peak = peak.max(ease_out_back_soft(t));
        }
        assert!(
            peak > 1.005 && peak < 1.035,
            "expected subtle soft back overshoot, got {peak}"
        );
    }

    #[test]
    fn directional_transition_glides_both_layers_and_clears_ghost_on_settle() {
        let mut tr = DirectionalTransition::new(0u8);
        assert!(!tr.is_active());
        assert_eq!(tr.active(), 0);
        assert_eq!(tr.page_rail_dx(52.0), 0.0);
        assert_eq!(tr.page_opacity(), 1.0);
        assert!(tr.exiting_layer(28.0).is_none());

        // Forward transition (right): page_rail_dx starts at +52.0 and decays monotonically to 0.0
        tr.transition_to(3, 1, false);
        assert!(tr.is_active());
        assert_eq!(tr.active(), 3);
        assert!((tr.page_rail_dx(52.0) - 52.0).abs() < 0.01);
        assert!((tr.page_opacity() - 0.48).abs() < 0.01);

        // Frame-0 clock-poisoning guard: even a 90ms cold first-frame stall advances by <= 12ms!
        let mut now = Instant::now();
        tr.tick(now);
        now += Duration::from_millis(90);
        tr.tick(now);
        let after_stall_dx = tr.page_rail_dx(52.0);
        assert!(
            after_stall_dx > 46.0,
            "Frame-0 clock guard must prevent first-frame teleport, got dx={after_stall_dx}"
        );

        let mut prev_rail = after_stall_dx;
        for _step in 1..=40 {
            now += Duration::from_millis(8);
            tr.tick(now);
            let rail = tr.page_rail_dx(52.0);
            assert!(
                rail >= 0.0 && rail <= prev_rail + 1e-5,
                "forward page_rail_dx must decay monotonically toward 0.0: prev={prev_rail}, now={rail}"
            );
            prev_rail = rail;
        }
        assert_eq!(
            tr.page_rail_dx(52.0),
            0.0,
            "page_rail_dx must finish gliding cleanly by 280ms"
        );
        assert_eq!(tr.page_opacity(), 1.0);

        // Interrupt mid-flight going backward to tab 1: page_rail_dx starts at -52.0 -> 0.0
        tr.transition_to(1, -1, false);
        assert_eq!(tr.active(), 1);
        assert!((tr.page_rail_dx(52.0) + 52.0).abs() < 0.01);
        let mut prev_back_rail = tr.page_rail_dx(52.0);

        let mut frames = 0;
        while tr.tick(now) {
            now += Duration::from_millis(8);
            frames += 1;
            let rail = tr.page_rail_dx(52.0);
            assert!(
                rail <= 0.0 && rail >= prev_back_rail - 1e-5,
                "backward page_rail_dx must decay monotonically toward 0.0: prev={prev_back_rail}, now={rail}"
            );
            prev_back_rail = rail;
            assert!(frames < 200);
        }
        assert!(!tr.is_active());
        assert_eq!(tr.page_rail_dx(52.0), 0.0);
        assert_eq!(tr.page_opacity(), 1.0);
        assert!(tr.exiting_layer(28.0).is_none());

        // Reduce motion snaps cleanly with zero rail offset
        tr.transition_to(5, 1, true);
        assert!(!tr.is_active());
        assert_eq!(tr.active(), 5);
        assert_eq!(tr.page_rail_dx(52.0), 0.0);
        assert_eq!(tr.page_opacity(), 1.0);
    }

    #[test]
    fn page_choreo_pure_horizontal_in_place_symmetric_unfold_and_icon_bloom() {
        let settled = PageChoreo::settled();
        assert_eq!(settled.slot(0), SlotPose::SETTLED);
        assert_eq!(settled.tile(3, 2), SlotPose::SETTLED);
        assert_eq!(settled.inner_bloom(1, 2), SlotPose::SETTLED);
        assert_eq!(settled.icon_scale(1, 2), 1.0);
        assert!(SlotPose::SETTLED.is_settled());
        assert_eq!(SlotPose::SETTLED.inset_px, 0.0);
        assert_eq!(SlotPose::SETTLED.shadow_alpha, 1.0);

        // STRICTLY dx == 0.0 && dy == 0.0 ALWAYS on BOTH tile() and inner_bloom() across all
        // tiers, sub_idx, directions, and timestamps — mathematically impossible to fly diagonally!
        for dir in [-1_i8, 1_i8] {
            for elapsed_s in [0.0_f32, 0.03, 0.08, 0.14, 0.22, 0.32, 0.42] {
                let choreo = PageChoreo {
                    elapsed_s,
                    direction: dir,
                    active: true,
                };
                for tier in 0..=5 {
                    for sub_idx in 0..=5 {
                        let card = choreo.tile(tier, sub_idx);
                        assert_eq!(card.dx, 0.0, "tile dx must ALWAYS be 0.0");
                        assert_eq!(card.dy, 0.0, "tile dy must ALWAYS be 0.0");
                        assert_eq!(card.scale, 1.0, "outer Bento tile scale stays 1.0");
                        assert!(
                            (0.0..=11.001).contains(&card.inset_px),
                            "tile inset_px out of range: {}",
                            card.inset_px
                        );
                        assert!(
                            (0.0..=1.0).contains(&card.shadow_alpha),
                            "tile shadow_alpha out of range: {}",
                            card.shadow_alpha
                        );
                        assert!(
                            (0.30..=1.0).contains(&card.opacity),
                            "tile opacity must stay visible (>= 0.30), got {}",
                            card.opacity
                        );

                        let bloom = choreo.inner_bloom(tier, sub_idx);
                        assert_eq!(bloom.dx, 0.0, "inner_bloom dx must ALWAYS be 0.0");
                        assert_eq!(bloom.dy, 0.0, "inner_bloom dy must ALWAYS be 0.0");
                        assert_eq!(
                            bloom.scale, 1.0,
                            "brand icon layout scale stays locked at 1.0"
                        );
                        assert!(
                            (0.0..=3.001).contains(&bloom.inset_px),
                            "inner_bloom inset_px out of range: {}",
                            bloom.inset_px
                        );
                        assert!(
                            (0.28..=1.0).contains(&bloom.opacity),
                            "inner_bloom opacity out of range: {}",
                            bloom.opacity
                        );
                    }
                }
            }
        }

        // inset_px starts at 11.0px and decays monotonically to 0.0 while shadow_alpha blooms 0.0 -> 1.0
        let mut prev_inset = 11.0_f32;
        let mut prev_shadow = 0.0_f32;
        for step in 0..=45 {
            let t = step as f32 * 0.01;
            let pose = PageChoreo {
                elapsed_s: t,
                direction: 1,
                active: true,
            }
            .tile(0, 1);
            assert!(
                pose.inset_px <= prev_inset + 1e-5,
                "tile inset_px must decay monotonically: prev={prev_inset}, now={} at t={t}",
                pose.inset_px
            );
            assert!(
                pose.shadow_alpha >= prev_shadow - 1e-5,
                "tile shadow_alpha must rise monotonically: prev={prev_shadow}, now={} at t={t}",
                pose.shadow_alpha
            );
            prev_inset = pose.inset_px;
            prev_shadow = pose.shadow_alpha;
        }
        assert_eq!(prev_inset, 0.0);
        assert_eq!(prev_shadow, 1.0);

        // Staggered sequential card_seq cascade: tile(0, 0) leads tile(0, 1) leads tile(1, 0) leads tile(1, 2)
        let mid = PageChoreo {
            elapsed_s: 0.14,
            direction: 1,
            active: true,
        };
        let c0 = mid.tile(0, 0);
        let c1 = mid.tile(0, 1);
        let c2 = mid.tile(1, 0);
        let c4 = mid.tile(1, 2);
        assert!(
            c0.inset_px < c1.inset_px && c1.inset_px < c2.inset_px && c2.inset_px < c4.inset_px,
            "expected sequential inset_px cascade: c0={}, c1={}, c2={}, c4={}",
            c0.inset_px,
            c1.inset_px,
            c2.inset_px,
            c4.inset_px
        );

        // Late elapsed time settles cleanly at CHOREO_SETTLE_S (0.42s)
        let late = PageChoreo {
            elapsed_s: CHOREO_SETTLE_S,
            direction: 1,
            active: true,
        };
        assert!(late.tile(0, 0).is_settled());
        assert!(late.tile(1, 1).is_settled());
        assert!(late.tile(3, 3).is_settled());
        assert!(late.inner_bloom(4, 5).is_settled());

        // DirectionalTransition choreo settles to exact SlotPose::SETTLED once finished
        let mut tr = DirectionalTransition::new(0u8);
        tr.transition_to(2, 1, false);
        let mut now = Instant::now();
        while tr.tick(now) {
            now += Duration::from_millis(8);
        }
        assert_eq!(tr.choreo().tile(2, 1), SlotPose::SETTLED);
    }

    #[test]
    fn active_icon_bloom_scale_and_dy_bloom_and_settle_cleanly() {
        let mut tr = DirectionalTransition::new(0u8);
        assert_eq!(tr.active_icon_bloom_scale(), 1.0);
        assert_eq!(tr.active_icon_bloom_dy(), 0.0);

        tr.transition_to(1, 1, false);
        assert!((tr.active_icon_bloom_scale() - 0.82).abs() < 0.01);

        let mut now = Instant::now();
        let mut min_dy = 0.0_f32;
        let mut max_scale = 0.0_f32;
        while tr.tick(now) {
            min_dy = min_dy.min(tr.active_icon_bloom_dy());
            max_scale = max_scale.max(tr.active_icon_bloom_scale());
            now += Duration::from_millis(8);
        }
        assert!(
            (1.02..1.07).contains(&max_scale),
            "expected crisp Dock icon scale bloom near 1.04, got {max_scale}"
        );
        assert!(
            (-1.50..-1.0).contains(&min_dy),
            "expected gentle upward Dock micro-lift near -1.4px, got {min_dy}"
        );
        assert_eq!(tr.active_icon_bloom_scale(), 1.0);
        assert_eq!(tr.active_icon_bloom_dy(), 0.0);
    }
}
