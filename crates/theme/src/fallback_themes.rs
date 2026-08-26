use std::sync::Arc;

use gpui::{FontStyle, FontWeight, HighlightStyle, Hsla, WindowBackgroundAppearance, hsla};

use crate::{
    AccentColors, Appearance, DEFAULT_DARK_THEME, PlayerColor, PlayerColors, StatusColors,
    StatusColorsRefinement, SyntaxTheme, SystemColors, Theme, ThemeColors, ThemeColorsRefinement,
    ThemeFamily, ThemeStyles, default_color_scales,
};

/// The default theme family for Zed.
///
/// This is used to construct the default theme fallback values, as well as to
/// have a theme available at compile time for tests.
pub fn zed_default_themes() -> ThemeFamily {
    ThemeFamily {
        id: "zed-default".to_string(),
        name: "Zed Default".into(),
        author: "".into(),
        themes: vec![zed_default_dark(), khala_dark(), sarah_dark()],
        scales: default_color_scales(),
    }
}

// If a theme customizes a foreground version of a status color, but does not
// customize the background color, then use a partly-transparent version of the
// foreground color for the background color.
/// Applies default status color backgrounds from their foreground counterparts.
pub fn apply_status_color_defaults(status: &mut StatusColorsRefinement) {
    for (fg_color, bg_color) in [
        (&status.deleted, &mut status.deleted_background),
        (&status.created, &mut status.created_background),
        (&status.modified, &mut status.modified_background),
        (&status.conflict, &mut status.conflict_background),
        (&status.error, &mut status.error_background),
        (&status.hidden, &mut status.hidden_background),
    ] {
        if bg_color.is_none()
            && let Some(fg_color) = fg_color
        {
            *bg_color = Some(fg_color.opacity(0.25));
        }
    }
}

/// Applies default theme color values derived from player colors.
pub fn apply_theme_color_defaults(
    theme_colors: &mut ThemeColorsRefinement,
    player_colors: &PlayerColors,
) {
    if theme_colors.element_selection_background.is_none() {
        let mut selection = player_colors.local().selection;
        if selection.a == 1.0 {
            selection.a = 0.25;
        }
        theme_colors.element_selection_background = Some(selection);
    }
}

pub(crate) fn zed_default_dark() -> Theme {
    let bg = hsla(215. / 360., 12. / 100., 15. / 100., 1.);
    let editor = hsla(220. / 360., 12. / 100., 18. / 100., 1.);
    let elevated_surface = hsla(225. / 360., 12. / 100., 17. / 100., 1.);
    let hover = hsla(225.0 / 360., 11.8 / 100., 26.7 / 100., 1.0);

    let blue = hsla(207.8 / 360., 81. / 100., 66. / 100., 1.0);
    let gray = hsla(218.8 / 360., 10. / 100., 40. / 100., 1.0);
    let green = hsla(95. / 360., 38. / 100., 62. / 100., 1.0);
    let orange = hsla(29. / 360., 54. / 100., 61. / 100., 1.0);
    let purple = hsla(286. / 360., 51. / 100., 64. / 100., 1.0);
    let red = hsla(355. / 360., 65. / 100., 65. / 100., 1.0);
    let teal = hsla(187. / 360., 47. / 100., 55. / 100., 1.0);
    let yellow = hsla(39. / 360., 67. / 100., 69. / 100., 1.0);

    const ADDED_COLOR: Hsla = Hsla {
        h: 134. / 360.,
        s: 0.55,
        l: 0.40,
        a: 1.0,
    };
    const WORD_ADDED_COLOR: Hsla = Hsla {
        h: 134. / 360.,
        s: 0.55,
        l: 0.40,
        a: 0.35,
    };
    const MODIFIED_COLOR: Hsla = Hsla {
        h: 48. / 360.,
        s: 0.76,
        l: 0.47,
        a: 1.0,
    };
    const REMOVED_COLOR: Hsla = Hsla {
        h: 350. / 360.,
        s: 0.88,
        l: 0.25,
        a: 1.0,
    };
    const WORD_DELETED_COLOR: Hsla = Hsla {
        h: 350. / 360.,
        s: 0.88,
        l: 0.25,
        a: 0.80,
    };

    let player = PlayerColors::dark();
    Theme {
        id: "one_dark".to_string(),
        name: DEFAULT_DARK_THEME.into(),
        appearance: Appearance::Dark,
        styles: ThemeStyles {
            window_background_appearance: WindowBackgroundAppearance::Opaque,
            system: SystemColors::default(),
            accents: AccentColors(Arc::from(vec![
                blue, orange, purple, teal, red, green, yellow,
            ])),
            colors: ThemeColors {
                border: hsla(225. / 360., 13. / 100., 12. / 100., 1.),
                border_variant: hsla(228. / 360., 8. / 100., 25. / 100., 1.),
                border_focused: hsla(223. / 360., 78. / 100., 65. / 100., 1.),
                border_selected: hsla(222.6 / 360., 77.5 / 100., 65.1 / 100., 1.0),
                border_transparent: SystemColors::default().transparent,
                border_disabled: hsla(222.0 / 360., 11.6 / 100., 33.7 / 100., 1.0),
                elevated_surface_background: elevated_surface,
                surface_background: bg,
                background: bg,
                element_background: hsla(223.0 / 360., 13. / 100., 21. / 100., 1.0),
                element_hover: hover,
                element_active: hsla(220.0 / 360., 11.8 / 100., 20.0 / 100., 1.0),
                element_selected: hsla(224.0 / 360., 11.3 / 100., 26.1 / 100., 1.0),
                element_disabled: SystemColors::default().transparent,
                element_selection_background: player.local().selection.alpha(0.25),
                drop_target_background: hsla(220.0 / 360., 8.3 / 100., 21.4 / 100., 1.0),
                drop_target_border: hsla(221. / 360., 11. / 100., 86. / 100., 1.0),
                ghost_element_background: SystemColors::default().transparent,
                ghost_element_hover: hover,
                ghost_element_active: hsla(220.0 / 360., 11.8 / 100., 20.0 / 100., 1.0),
                ghost_element_selected: hsla(224.0 / 360., 11.3 / 100., 26.1 / 100., 1.0),
                ghost_element_disabled: SystemColors::default().transparent,
                text: hsla(221. / 360., 11. / 100., 86. / 100., 1.0),
                text_muted: hsla(218.0 / 360., 7. / 100., 46. / 100., 1.0),
                text_placeholder: hsla(220.0 / 360., 6.6 / 100., 44.5 / 100., 1.0),
                text_disabled: hsla(220.0 / 360., 6.6 / 100., 44.5 / 100., 1.0),
                text_accent: hsla(222.6 / 360., 77.5 / 100., 65.1 / 100., 1.0),
                icon: hsla(222.9 / 360., 9.9 / 100., 86.1 / 100., 1.0),
                icon_muted: hsla(220.0 / 360., 12.1 / 100., 66.1 / 100., 1.0),
                icon_disabled: hsla(220.0 / 360., 6.4 / 100., 45.7 / 100., 1.0),
                icon_placeholder: hsla(220.0 / 360., 6.4 / 100., 45.7 / 100., 1.0),
                icon_accent: blue,
                debugger_accent: red,
                status_bar_background: bg,
                title_bar_background: bg,
                title_bar_inactive_background: bg,
                toolbar_background: editor,
                tab_bar_background: bg,
                tab_inactive_background: bg,
                tab_active_background: editor,
                search_match_background: bg,
                search_active_match_background: bg,

                editor_background: editor,
                editor_gutter_background: editor,
                editor_subheader_background: bg,
                editor_active_line_background: hsla(222.9 / 360., 13.5 / 100., 20.4 / 100., 1.0),
                editor_highlighted_line_background: hsla(207.8 / 360., 81. / 100., 66. / 100., 0.1),
                editor_debugger_active_line_background: hsla(
                    207.8 / 360.,
                    81. / 100.,
                    66. / 100.,
                    0.2,
                ),
                editor_line_number: hsla(222.0 / 360., 11.5 / 100., 34.1 / 100., 1.0),
                editor_active_line_number: hsla(216.0 / 360., 5.9 / 100., 49.6 / 100., 1.0),
                editor_hover_line_number: hsla(216.0 / 360., 5.9 / 100., 56.7 / 100., 1.0),
                editor_invisible: hsla(222.0 / 360., 11.5 / 100., 34.1 / 100., 1.0),
                editor_wrap_guide: hsla(228. / 360., 8. / 100., 25. / 100., 1.),
                editor_active_wrap_guide: hsla(228. / 360., 8. / 100., 25. / 100., 1.),
                editor_indent_guide: hsla(228. / 360., 8. / 100., 25. / 100., 1.),
                editor_indent_guide_active: hsla(225. / 360., 13. / 100., 12. / 100., 1.),
                editor_document_highlight_read_background: hsla(
                    207.8 / 360.,
                    81. / 100.,
                    66. / 100.,
                    0.2,
                ),
                editor_document_highlight_write_background: gpui::red(),
                editor_document_highlight_bracket_background: gpui::green(),
                editor_diff_hunk_added_background: ADDED_COLOR.opacity(0.12),
                editor_diff_hunk_added_hollow_background: ADDED_COLOR.opacity(0.06),
                editor_diff_hunk_added_hollow_border: ADDED_COLOR.opacity(0.36),
                editor_diff_hunk_deleted_background: REMOVED_COLOR.opacity(0.12),
                editor_diff_hunk_deleted_hollow_background: REMOVED_COLOR.opacity(0.06),
                editor_diff_hunk_deleted_hollow_border: REMOVED_COLOR.opacity(0.36),

                terminal_background: bg,
                // todo("Use one colors for terminal")
                terminal_ansi_background: crate::black().dark().step_12(),
                terminal_foreground: crate::white().dark().step_12(),
                terminal_bright_foreground: crate::white().dark().step_11(),
                terminal_dim_foreground: crate::white().dark().step_10(),
                terminal_ansi_black: crate::black().dark().step_12(),
                terminal_ansi_red: crate::red().dark().step_11(),
                terminal_ansi_green: crate::green().dark().step_11(),
                terminal_ansi_yellow: crate::yellow().dark().step_11(),
                terminal_ansi_blue: crate::blue().dark().step_11(),
                terminal_ansi_magenta: crate::violet().dark().step_11(),
                terminal_ansi_cyan: crate::cyan().dark().step_11(),
                terminal_ansi_white: crate::neutral().dark().step_12(),
                terminal_ansi_bright_black: crate::black().dark().step_11(),
                terminal_ansi_bright_red: crate::red().dark().step_10(),
                terminal_ansi_bright_green: crate::green().dark().step_10(),
                terminal_ansi_bright_yellow: crate::yellow().dark().step_10(),
                terminal_ansi_bright_blue: crate::blue().dark().step_10(),
                terminal_ansi_bright_magenta: crate::violet().dark().step_10(),
                terminal_ansi_bright_cyan: crate::cyan().dark().step_10(),
                terminal_ansi_bright_white: crate::neutral().dark().step_11(),
                terminal_ansi_dim_black: crate::black().dark().step_10(),
                terminal_ansi_dim_red: crate::red().dark().step_9(),
                terminal_ansi_dim_green: crate::green().dark().step_9(),
                terminal_ansi_dim_yellow: crate::yellow().dark().step_9(),
                terminal_ansi_dim_blue: crate::blue().dark().step_9(),
                terminal_ansi_dim_magenta: crate::violet().dark().step_9(),
                terminal_ansi_dim_cyan: crate::cyan().dark().step_9(),
                terminal_ansi_dim_white: crate::neutral().dark().step_10(),
                panel_background: bg,
                panel_focused_border: blue,
                panel_indent_guide: hsla(228. / 360., 8. / 100., 25. / 100., 1.),
                panel_indent_guide_hover: hsla(225. / 360., 13. / 100., 12. / 100., 1.),
                panel_indent_guide_active: hsla(225. / 360., 13. / 100., 12. / 100., 1.),
                panel_overlay_background: bg,
                panel_overlay_hover: hover,
                pane_focused_border: blue,
                pane_group_border: hsla(225. / 360., 13. / 100., 12. / 100., 1.),
                scrollbar_thumb_background: gpui::transparent_black(),
                scrollbar_thumb_hover_background: hover,
                scrollbar_thumb_active_background: hsla(
                    225.0 / 360.,
                    11.8 / 100.,
                    26.7 / 100.,
                    1.0,
                ),
                scrollbar_thumb_border: hsla(228. / 360., 8. / 100., 25. / 100., 1.),
                scrollbar_track_background: gpui::transparent_black(),
                scrollbar_track_border: hsla(228. / 360., 8. / 100., 25. / 100., 1.),
                minimap_thumb_background: hsla(225.0 / 360., 11.8 / 100., 26.7 / 100., 0.7),
                minimap_thumb_hover_background: hsla(225.0 / 360., 11.8 / 100., 26.7 / 100., 0.7),
                minimap_thumb_active_background: hsla(225.0 / 360., 11.8 / 100., 26.7 / 100., 0.7),
                minimap_thumb_border: hsla(228. / 360., 8. / 100., 25. / 100., 1.),
                editor_foreground: hsla(218. / 360., 14. / 100., 71. / 100., 1.),
                link_text_hover: blue,
                version_control_added: ADDED_COLOR,
                version_control_deleted: REMOVED_COLOR,
                version_control_modified: MODIFIED_COLOR,
                version_control_renamed: MODIFIED_COLOR,
                version_control_conflict: crate::orange().light().step_12(),
                version_control_ignored: crate::gray().light().step_12(),
                version_control_word_added: WORD_ADDED_COLOR,
                version_control_word_deleted: WORD_DELETED_COLOR,
                version_control_conflict_marker_ours: crate::green().light().step_12().alpha(0.5),
                version_control_conflict_marker_theirs: crate::blue().light().step_12().alpha(0.5),

                vim_normal_background: SystemColors::default().transparent,
                vim_insert_background: SystemColors::default().transparent,
                vim_replace_background: SystemColors::default().transparent,
                vim_visual_background: SystemColors::default().transparent,
                vim_visual_line_background: SystemColors::default().transparent,
                vim_visual_block_background: SystemColors::default().transparent,
                vim_yank_background: hsla(207.8 / 360., 81. / 100., 66. / 100., 0.2),
                vim_helix_jump_label_foreground: red,
                vim_helix_normal_background: SystemColors::default().transparent,
                vim_helix_select_background: SystemColors::default().transparent,
                vim_normal_foreground: SystemColors::default().transparent,
                vim_insert_foreground: SystemColors::default().transparent,
                vim_replace_foreground: SystemColors::default().transparent,
                vim_visual_foreground: SystemColors::default().transparent,
                vim_visual_line_foreground: SystemColors::default().transparent,
                vim_visual_block_foreground: SystemColors::default().transparent,
                vim_helix_normal_foreground: SystemColors::default().transparent,
                vim_helix_select_foreground: SystemColors::default().transparent,
            },
            status: StatusColors {
                conflict: yellow,
                conflict_background: yellow,
                conflict_border: yellow,
                created: green,
                created_background: green,
                created_border: green,
                deleted: red,
                deleted_background: red,
                deleted_border: red,
                error: red,
                error_background: red,
                error_border: red,
                hidden: gray,
                hidden_background: gray,
                hidden_border: gray,
                hint: blue,
                hint_background: blue,
                hint_border: blue,
                ignored: gray,
                ignored_background: gray,
                ignored_border: gray,
                info: blue,
                info_background: blue,
                info_border: blue,
                modified: yellow,
                modified_background: yellow,
                modified_border: yellow,
                predictive: gray,
                predictive_background: gray,
                predictive_border: gray,
                renamed: blue,
                renamed_background: blue,
                renamed_border: blue,
                success: green,
                success_background: green,
                success_border: green,
                unreachable: gray,
                unreachable_background: gray,
                unreachable_border: gray,
                warning: yellow,
                warning_background: yellow,
                warning_border: yellow,
            },
            player,
            syntax: Arc::new(SyntaxTheme::new(vec![
                ("attribute".into(), purple.into()),
                ("boolean".into(), orange.into()),
                ("comment".into(), gray.into()),
                ("comment.doc".into(), gray.into()),
                ("constant".into(), yellow.into()),
                ("constructor".into(), blue.into()),
                ("embedded".into(), HighlightStyle::default()),
                (
                    "emphasis".into(),
                    HighlightStyle {
                        font_style: Some(FontStyle::Italic),
                        ..HighlightStyle::default()
                    },
                ),
                (
                    "emphasis.strong".into(),
                    HighlightStyle {
                        font_weight: Some(FontWeight::BOLD),
                        ..HighlightStyle::default()
                    },
                ),
                ("enum".into(), teal.into()),
                ("function".into(), blue.into()),
                ("function.method".into(), blue.into()),
                ("function.definition".into(), blue.into()),
                ("hint".into(), blue.into()),
                ("keyword".into(), purple.into()),
                ("label".into(), HighlightStyle::default()),
                ("link_text".into(), blue.into()),
                (
                    "link_uri".into(),
                    HighlightStyle {
                        color: Some(teal),
                        font_style: Some(FontStyle::Italic),
                        ..HighlightStyle::default()
                    },
                ),
                ("number".into(), orange.into()),
                ("operator".into(), HighlightStyle::default()),
                ("predictive".into(), HighlightStyle::default()),
                ("preproc".into(), purple.into()),
                ("primary".into(), HighlightStyle::default()),
                ("property".into(), red.into()),
                ("punctuation".into(), HighlightStyle::default()),
                ("punctuation.bracket".into(), HighlightStyle::default()),
                ("punctuation.delimiter".into(), HighlightStyle::default()),
                ("punctuation.list_marker".into(), HighlightStyle::default()),
                ("punctuation.special".into(), HighlightStyle::default()),
                ("string".into(), green.into()),
                ("string.escape".into(), HighlightStyle::default()),
                ("string.regex".into(), red.into()),
                ("string.special".into(), HighlightStyle::default()),
                ("string.special.symbol".into(), HighlightStyle::default()),
                ("tag".into(), HighlightStyle::default()),
                ("text.literal".into(), HighlightStyle::default()),
                ("title".into(), HighlightStyle::default()),
                ("type".into(), teal.into()),
                ("variable".into(), HighlightStyle::default()),
                ("variable.special".into(), red.into()),
                ("variant".into(), HighlightStyle::default()),
                ("diff.plus".into(), green.into()),
                ("diff.minus".into(), red.into()),
            ])),
        },
    }
}

pub(crate) fn khala_dark() -> Theme {
    // Khala — the shared OpenAgents brand dark theme (O1-P3). Compiled-in
    // port of the Aiur token family (assets/themes/aiur/aiur.json): the same
    // Protoss-blue system the JSON theme carries, exposed under the Khala
    // brand identity. Values follow the O1-P1 branding package token table.
    let accent = hsla(217.22 / 360., 91.22 / 100., 59.8 / 100., 1.0);
    let accent_hover = hsla(217.69 / 360., 91.76 / 100., 66.67 / 100., 1.0);
    let accent_active = hsla(218.31 / 360., 74.06 / 100., 53.14 / 100., 1.0);
    let focus = hsla(213.12 / 360., 93.9 / 100., 67.84 / 100., 1.0);
    let blue_200 = hsla(220.71 / 360., 1.0, 78.04 / 100., 1.0);
    let void = hsla(225.0 / 360., 44.44 / 100., 3.53 / 100., 1.0);
    let surface = hsla(220.0 / 360., 48.84 / 100., 8.43 / 100., 1.0);
    let surface_raised = hsla(220.59 / 360., 45.95 / 100., 14.51 / 100., 1.0);
    let surface_overlay = hsla(219.0 / 360., 45.45 / 100., 17.25 / 100., 1.0);
    let border = hsla(221.05 / 360., 38.0 / 100., 19.61 / 100., 1.0);
    let border_variant = hsla(223.33 / 360., 45.0 / 100., 15.69 / 100., 1.0);
    let border_strong = hsla(221.45 / 360., 38.46 / 100., 28.04 / 100., 1.0);
    let text = hsla(222.35 / 360., 1.0, 96.67 / 100., 1.0);
    let text_body = hsla(220.65 / 360., 60.78 / 100., 90.0 / 100., 1.0);
    let text_muted = hsla(218.75 / 360., 28.57 / 100., 67.06 / 100., 1.0);
    let text_faint = hsla(228.33 / 360., 18.0 / 100., 60.78 / 100., 1.0);
    let text_disabled = hsla(223.02 / 360., 23.77 / 100., 43.73 / 100., 1.0);
    let muted = hsla(229.33 / 360., 35.43 / 100., 75.1 / 100., 1.0);
    let info_cyan = hsla(198.44 / 360., 93.2 / 100., 59.61 / 100., 1.0);
    let success_green = hsla(142.09 / 360., 70.56 / 100., 45.29 / 100., 1.0);
    let warning_amber = hsla(37.69 / 360., 92.13 / 100., 50.2 / 100., 1.0);
    let error_red = hsla(0.0 / 360., 90.6 / 100., 70.78 / 100., 1.0);
    let amber = hsla(35.5 / 360., 65.93 / 100., 64.31 / 100., 1.0);
    let red = hsla(348.84 / 360., 88.97 / 100., 71.57 / 100., 1.0);
    let orange = hsla(22.45 / 360., 1.0, 69.61 / 100., 1.0);
    let green = hsla(88.8 / 360., 50.51 / 100., 61.18 / 100., 1.0);
    let magenta = hsla(261.29 / 360., 85.32 / 100., 78.63 / 100., 1.0);
    let cyan = hsla(202.15 / 360., 1.0, 74.51 / 100., 1.0);

    Theme {
        id: "khala".to_string(),
        name: "Khala".into(),
        appearance: Appearance::Dark,
        styles: ThemeStyles {
            window_background_appearance: WindowBackgroundAppearance::Opaque,
            system: SystemColors::default(),
            accents: AccentColors::dark(),
            colors: ThemeColors {
                border,
                border_variant,
                border_focused: focus,
                border_selected: border_strong,
                border_transparent: SystemColors::default().transparent,
                border_disabled: border_strong,
                elevated_surface_background: surface_raised,
                surface_background: surface,
                background: surface,
                element_background: surface_raised,
                element_hover: blue_200.opacity(20. / 255.),
                element_active: blue_200.opacity(33. / 255.),
                element_selected: accent.opacity(41. / 255.),
                element_disabled: surface,
                element_selection_background: accent.opacity(41. / 255.),
                drop_target_background: accent.opacity(128. / 255.),
                drop_target_border: focus,
                ghost_element_background: SystemColors::default().transparent,
                ghost_element_hover: blue_200.opacity(20. / 255.),
                ghost_element_active: blue_200.opacity(33. / 255.),
                ghost_element_selected: accent.opacity(41. / 255.),
                ghost_element_disabled: surface,
                text,
                text_muted,
                text_placeholder: text_faint,
                text_disabled,
                text_accent: accent,
                icon: text,
                icon_muted: text_muted,
                icon_disabled: text_disabled,
                icon_placeholder: text_faint,
                icon_accent: accent,
                debugger_accent: error_red,
                status_bar_background: surface,
                title_bar_background: surface,
                title_bar_inactive_background: void,
                toolbar_background: void,
                tab_bar_background: surface,
                tab_inactive_background: surface,
                tab_active_background: void,
                search_match_background: accent.opacity(102. / 255.),
                search_active_match_background: amber.opacity(102. / 255.),
                panel_background: surface,
                panel_focused_border: focus,
                panel_indent_guide: border_variant,
                panel_indent_guide_hover: border_strong,
                panel_indent_guide_active: border_strong,
                panel_overlay_background: surface_overlay,
                panel_overlay_hover: border,
                pane_focused_border: focus,
                pane_group_border: border,
                scrollbar_thumb_background: muted.opacity(76. / 255.),
                scrollbar_thumb_hover_background: border_strong,
                scrollbar_thumb_active_background: border_strong,
                scrollbar_thumb_border: border,
                scrollbar_track_background: SystemColors::default().transparent,
                scrollbar_track_border: border_variant,
                editor_foreground: text_body,
                editor_background: void,
                editor_gutter_background: void,
                editor_subheader_background: surface,
                editor_active_line_background: surface_raised.opacity(191. / 255.),
                editor_highlighted_line_background: surface_raised,
                editor_line_number: border_strong,
                editor_active_line_number: text_faint,
                editor_hover_line_number: text_body,
                editor_invisible: border_strong,
                editor_wrap_guide: muted.opacity(13. / 255.),
                editor_active_wrap_guide: muted.opacity(26. / 255.),
                editor_document_highlight_read_background: accent.opacity(26. / 255.),
                editor_document_highlight_write_background: border_strong.opacity(102. / 255.),
                terminal_background: void,
                terminal_foreground: text,
                terminal_bright_foreground: text,
                terminal_dim_foreground: text_disabled,
                terminal_ansi_background: void,
                terminal_ansi_black: border_strong,
                terminal_ansi_bright_black: text_disabled,
                terminal_ansi_dim_black: border,
                terminal_ansi_red: red,
                terminal_ansi_bright_red: hsla(349.89 / 360., 1.0, 81.37 / 100., 1.0),
                terminal_ansi_dim_red: hsla(347.55 / 360., 47.32 / 100., 56.08 / 100., 1.0),
                terminal_ansi_green: green,
                terminal_ansi_bright_green: hsla(87.91 / 360., 58.11 / 100., 70.98 / 100., 1.0),
                terminal_ansi_dim_green: hsla(87.69 / 360., 32.77 / 100., 46.67 / 100., 1.0),
                terminal_ansi_yellow: amber,
                terminal_ansi_bright_yellow: hsla(40.0 / 360., 80.0 / 100., 70.59 / 100., 1.0),
                terminal_ansi_dim_yellow: hsla(35.0 / 360., 37.8 / 100., 50.2 / 100., 1.0),
                terminal_ansi_blue: accent,
                terminal_ansi_bright_blue: accent_hover,
                terminal_ansi_dim_blue: accent_active,
                terminal_ansi_magenta: magenta,
                terminal_ansi_bright_magenta: hsla(264.3 / 360., 1.0, 84.51 / 100., 1.0),
                terminal_ansi_dim_magenta: hsla(264.0 / 360., 38.83 / 100., 59.61 / 100., 1.0),
                terminal_ansi_cyan: cyan,
                terminal_ansi_bright_cyan: hsla(199.18 / 360., 1.0, 80.98 / 100., 1.0),
                terminal_ansi_dim_cyan: hsla(197.14 / 360., 47.06 / 100., 53.33 / 100., 1.0),
                terminal_ansi_white: text,
                terminal_ansi_bright_white: hsla(0.0 / 360., 0.0 / 100., 100.0 / 100., 1.0),
                terminal_ansi_dim_white: muted,
                link_text_hover: accent_hover,
                version_control_added: success_green,
                version_control_deleted: error_red,
                version_control_modified: accent,
                version_control_renamed: accent,
                version_control_conflict: warning_amber,
                version_control_ignored: text_disabled,
                version_control_word_added: success_green.opacity(89. / 255.),
                version_control_word_deleted: error_red.opacity(204. / 255.),
                version_control_conflict_marker_ours: success_green.opacity(26. / 255.),
                version_control_conflict_marker_theirs: accent.opacity(26. / 255.),
                ..ThemeColors::dark()
            },
            status: StatusColors {
                conflict: warning_amber,
                conflict_background: warning_amber.opacity(26. / 255.),
                conflict_border: warning_amber.opacity(64. / 255.),
                created: success_green,
                created_background: success_green.opacity(26. / 255.),
                created_border: success_green.opacity(64. / 255.),
                deleted: error_red,
                deleted_background: error_red.opacity(26. / 255.),
                deleted_border: error_red.opacity(64. / 255.),
                error: error_red,
                error_background: error_red.opacity(26. / 255.),
                error_border: error_red.opacity(64. / 255.),
                hidden: text_disabled,
                hidden_background: text_disabled.opacity(26. / 255.),
                hidden_border: border_strong,
                hint: text_faint,
                hint_background: focus.opacity(26. / 255.),
                hint_border: border_strong,
                ignored: text_disabled,
                ignored_background: text_disabled.opacity(26. / 255.),
                ignored_border: border,
                info: info_cyan,
                info_background: info_cyan.opacity(26. / 255.),
                info_border: border_strong,
                modified: warning_amber,
                modified_background: warning_amber.opacity(26. / 255.),
                modified_border: warning_amber.opacity(64. / 255.),
                predictive: text_faint,
                predictive_background: text_faint.opacity(26. / 255.),
                predictive_border: border_strong,
                renamed: accent,
                renamed_background: accent.opacity(26. / 255.),
                renamed_border: border_strong,
                success: success_green,
                success_background: success_green.opacity(26. / 255.),
                success_border: success_green.opacity(64. / 255.),
                unreachable: muted,
                unreachable_background: muted.opacity(26. / 255.),
                unreachable_border: border,
                warning: warning_amber,
                warning_background: warning_amber.opacity(26. / 255.),
                warning_border: warning_amber.opacity(64. / 255.),
            },
            player: PlayerColors(vec![
                PlayerColor {
                    cursor: accent,
                    background: accent,
                    selection: accent.opacity(77. / 255.),
                },
                PlayerColor {
                    cursor: red,
                    background: red,
                    selection: red.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: orange,
                    background: orange,
                    selection: orange.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: magenta,
                    background: magenta,
                    selection: magenta.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: cyan,
                    background: cyan,
                    selection: cyan.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: error_red,
                    background: error_red,
                    selection: error_red.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: amber,
                    background: amber,
                    selection: amber.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: green,
                    background: green,
                    selection: green.opacity(61. / 255.),
                },
            ]),
            syntax: Arc::new(SyntaxTheme::new(vec![
                ("attribute".into(), accent.into()),
                ("boolean".into(), orange.into()),
                ("comment".into(), text_faint.into()),
                ("comment.doc".into(), muted.into()),
                ("constant".into(), amber.into()),
                ("constructor".into(), accent.into()),
                ("embedded".into(), text.into()),
                ("emphasis".into(), accent.into()),
                (
                    "emphasis.strong".into(),
                    HighlightStyle {
                        color: Some(orange),
                        font_weight: Some(FontWeight::BOLD),
                        ..HighlightStyle::default()
                    },
                ),
                ("enum".into(), cyan.into()),
                ("function".into(), accent.into()),
                ("hint".into(), text_faint.into()),
                ("keyword".into(), magenta.into()),
                ("label".into(), accent.into()),
                (
                    "link_text".into(),
                    HighlightStyle {
                        color: Some(accent),
                        font_style: Some(FontStyle::Italic),
                        ..HighlightStyle::default()
                    },
                ),
                ("link_uri".into(), cyan.into()),
                ("namespace".into(), text.into()),
                ("number".into(), orange.into()),
                ("operator".into(), cyan.into()),
                (
                    "predictive".into(),
                    HighlightStyle {
                        color: Some(text_faint),
                        font_style: Some(FontStyle::Italic),
                        ..HighlightStyle::default()
                    },
                ),
                ("preproc".into(), magenta.into()),
                ("primary".into(), muted.into()),
                ("property".into(), red.into()),
                ("punctuation".into(), muted.into()),
                ("punctuation.bracket".into(), muted.into()),
                ("punctuation.delimiter".into(), muted.into()),
                ("punctuation.list_marker".into(), red.into()),
                ("punctuation.markup".into(), red.into()),
                ("punctuation.special".into(), orange.into()),
                ("selector".into(), amber.into()),
                ("selector.pseudo".into(), accent.into()),
                ("string".into(), green.into()),
                ("string.escape".into(), muted.into()),
                ("string.regex".into(), orange.into()),
                ("string.special".into(), orange.into()),
                ("string.special.symbol".into(), orange.into()),
                ("tag".into(), accent.into()),
                ("text.literal".into(), green.into()),
                ("title".into(), red.into()),
                ("type".into(), cyan.into()),
                ("variable".into(), muted.into()),
                ("variable.parameter".into(), red.into()),
                ("variable.special".into(), orange.into()),
                ("variant".into(), accent.into()),
                ("diff.plus".into(), green.into()),
                ("diff.minus".into(), red.into()),
            ])),
        },
    }
}

pub(crate) fn sarah_dark() -> Theme {
    // Sarah — the OpenAgents voice-interface brand dark theme (O1-P4).
    // Compiled-in companion to Khala following the O1-P3 pattern: a warm
    // near-black navy system with a single warm gold/amber accent, ported
    // from the Sarah design tokens (planning/omega-ui-upgrade design-plan.md).
    // Sarah is the voice-interface persona: the interface keeps one visual
    // "pop" — the gold accent — against an otherwise monochrome dark palette.
    let accent = hsla(41.18 / 360., 62.0 / 100., 55.0 / 100., 1.0); // #d4a843
    let accent_hover = hsla(41.18 / 360., 66.0 / 100., 63.0 / 100., 1.0); // #e2bf62
    let accent_active = hsla(41.18 / 360., 56.0 / 100., 46.0 / 100., 1.0); // #b88f35
    let focus = hsla(41.18 / 360., 66.0 / 100., 63.0 / 100., 1.0); // gold focus ring
    let gold_300 = hsla(41.18 / 360., 78.0 / 100., 75.0 / 100., 1.0); // #f0d58a
    let void = hsla(224.0 / 360., 30.0 / 100., 6.0 / 100., 1.0); // #0b0f1a
    let surface = hsla(224.0 / 360., 34.0 / 100., 8.0 / 100., 1.0); // #0d111c
    let surface_raised = hsla(224.0 / 360., 33.0 / 100., 15.0 / 100., 1.0); // #1a2035
    let surface_overlay = hsla(222.0 / 360., 31.0 / 100., 19.0 / 100., 1.0); // #242b3a
    let border = hsla(222.0 / 360., 31.0 / 100., 18.0 / 100., 1.0); // #1e2436
    let border_variant = hsla(223.0 / 360., 33.0 / 100., 15.0 / 100., 1.0); // #1a2035
    let border_strong = hsla(220.0 / 360., 30.0 / 100., 24.0 / 100., 1.0); // #2a3348
    let text = hsla(220.0 / 360., 15.0 / 100., 92.0 / 100., 1.0); // #e8ebf0
    let text_body = hsla(220.0 / 360., 14.0 / 100., 80.0 / 100., 1.0); // #c2c9d4
    let text_muted = hsla(220.0 / 360., 12.0 / 100., 67.0 / 100., 1.0); // #a0a8b8
    let text_faint = hsla(220.0 / 360., 10.0 / 100., 56.0 / 100., 1.0); // #8a93a3
    let text_disabled = hsla(220.0 / 360., 10.0 / 100., 34.0 / 100., 1.0); // #4a5160
    let muted = hsla(220.0 / 360., 12.0 / 100., 73.0 / 100., 1.0); // #b9c0cc
    let info_cyan = hsla(198.44 / 360., 93.2 / 100., 59.61 / 100., 1.0); // #38bdf8
    let success_green = hsla(142.09 / 360., 70.56 / 100., 45.29 / 100., 1.0); // #22c55e
    let warning_amber = hsla(37.69 / 360., 92.13 / 100., 50.2 / 100., 1.0); // #f59e0b
    let error_red = hsla(0.0 / 360., 90.6 / 100., 70.78 / 100., 1.0); // #f87171
    let amber = hsla(41.18 / 360., 66.0 / 100., 63.0 / 100., 1.0); // #e2bf62
    let red = hsla(348.84 / 360., 88.97 / 100., 71.57 / 100., 1.0);
    let orange = hsla(22.45 / 360., 1.0, 69.61 / 100., 1.0);
    let green = hsla(88.8 / 360., 50.51 / 100., 61.18 / 100., 1.0);
    let magenta = hsla(261.29 / 360., 85.32 / 100., 78.63 / 100., 1.0);
    let cyan = hsla(202.15 / 360., 1.0, 74.51 / 100., 1.0);

    Theme {
        id: "sarah".to_string(),
        name: "Sarah".into(),
        appearance: Appearance::Dark,
        styles: ThemeStyles {
            window_background_appearance: WindowBackgroundAppearance::Opaque,
            system: SystemColors::default(),
            accents: AccentColors::dark(),
            colors: ThemeColors {
                border,
                border_variant,
                border_focused: focus,
                border_selected: border_strong,
                border_transparent: SystemColors::default().transparent,
                border_disabled: border_strong,
                elevated_surface_background: surface_raised,
                surface_background: surface,
                background: surface,
                element_background: surface_raised,
                element_hover: gold_300.opacity(20. / 255.),
                element_active: gold_300.opacity(33. / 255.),
                element_selected: accent.opacity(41. / 255.),
                element_disabled: surface,
                element_selection_background: accent.opacity(41. / 255.),
                drop_target_background: accent.opacity(128. / 255.),
                drop_target_border: focus,
                ghost_element_background: SystemColors::default().transparent,
                ghost_element_hover: gold_300.opacity(20. / 255.),
                ghost_element_active: gold_300.opacity(33. / 255.),
                ghost_element_selected: accent.opacity(41. / 255.),
                ghost_element_disabled: surface,
                text,
                text_muted,
                text_placeholder: text_faint,
                text_disabled,
                text_accent: accent,
                icon: text,
                icon_muted: text_muted,
                icon_disabled: text_disabled,
                icon_placeholder: text_faint,
                icon_accent: accent,
                debugger_accent: error_red,
                status_bar_background: surface,
                title_bar_background: surface,
                title_bar_inactive_background: void,
                toolbar_background: void,
                tab_bar_background: surface,
                tab_inactive_background: surface,
                tab_active_background: void,
                search_match_background: accent.opacity(102. / 255.),
                search_active_match_background: amber.opacity(102. / 255.),
                panel_background: surface,
                panel_focused_border: focus,
                panel_indent_guide: border_variant,
                panel_indent_guide_hover: border_strong,
                panel_indent_guide_active: border_strong,
                panel_overlay_background: surface_overlay,
                panel_overlay_hover: border,
                pane_focused_border: focus,
                pane_group_border: border,
                scrollbar_thumb_background: muted.opacity(76. / 255.),
                scrollbar_thumb_hover_background: border_strong,
                scrollbar_thumb_active_background: border_strong,
                scrollbar_thumb_border: border,
                scrollbar_track_background: SystemColors::default().transparent,
                scrollbar_track_border: border_variant,
                editor_foreground: text_body,
                editor_background: void,
                editor_gutter_background: void,
                editor_subheader_background: surface,
                editor_active_line_background: surface_raised.opacity(191. / 255.),
                editor_highlighted_line_background: surface_raised,
                editor_line_number: border_strong,
                editor_active_line_number: text_faint,
                editor_hover_line_number: text_body,
                editor_invisible: border_strong,
                editor_wrap_guide: muted.opacity(13. / 255.),
                editor_active_wrap_guide: muted.opacity(26. / 255.),
                editor_document_highlight_read_background: accent.opacity(26. / 255.),
                editor_document_highlight_write_background: border_strong.opacity(102. / 255.),
                terminal_background: void,
                terminal_foreground: text,
                terminal_bright_foreground: text,
                terminal_dim_foreground: text_disabled,
                terminal_ansi_background: void,
                terminal_ansi_black: border_strong,
                terminal_ansi_bright_black: text_disabled,
                terminal_ansi_dim_black: border,
                terminal_ansi_red: red,
                terminal_ansi_bright_red: hsla(349.89 / 360., 1.0, 81.37 / 100., 1.0),
                terminal_ansi_dim_red: hsla(347.55 / 360., 47.32 / 100., 56.08 / 100., 1.0),
                terminal_ansi_green: green,
                terminal_ansi_bright_green: hsla(87.91 / 360., 58.11 / 100., 70.98 / 100., 1.0),
                terminal_ansi_dim_green: hsla(87.69 / 360., 32.77 / 100., 46.67 / 100., 1.0),
                terminal_ansi_yellow: amber,
                terminal_ansi_bright_yellow: hsla(40.0 / 360., 80.0 / 100., 70.59 / 100., 1.0),
                terminal_ansi_dim_yellow: hsla(35.0 / 360., 37.8 / 100., 50.2 / 100., 1.0),
                terminal_ansi_blue: accent,
                terminal_ansi_bright_blue: accent_hover,
                terminal_ansi_dim_blue: accent_active,
                terminal_ansi_magenta: magenta,
                terminal_ansi_bright_magenta: hsla(264.3 / 360., 1.0, 84.51 / 100., 1.0),
                terminal_ansi_dim_magenta: hsla(264.0 / 360., 38.83 / 100., 59.61 / 100., 1.0),
                terminal_ansi_cyan: cyan,
                terminal_ansi_bright_cyan: hsla(199.18 / 360., 1.0, 80.98 / 100., 1.0),
                terminal_ansi_dim_cyan: hsla(197.14 / 360., 47.06 / 100., 53.33 / 100., 1.0),
                terminal_ansi_white: text,
                terminal_ansi_bright_white: hsla(0.0 / 360., 0.0 / 100., 100.0 / 100., 1.0),
                terminal_ansi_dim_white: muted,
                link_text_hover: accent_hover,
                version_control_added: success_green,
                version_control_deleted: error_red,
                version_control_modified: accent,
                version_control_renamed: accent,
                version_control_conflict: warning_amber,
                version_control_ignored: text_disabled,
                version_control_word_added: success_green.opacity(89. / 255.),
                version_control_word_deleted: error_red.opacity(204. / 255.),
                version_control_conflict_marker_ours: success_green.opacity(26. / 255.),
                version_control_conflict_marker_theirs: accent.opacity(26. / 255.),
                ..ThemeColors::dark()
            },
            status: StatusColors {
                conflict: warning_amber,
                conflict_background: warning_amber.opacity(26. / 255.),
                conflict_border: warning_amber.opacity(64. / 255.),
                created: success_green,
                created_background: success_green.opacity(26. / 255.),
                created_border: success_green.opacity(64. / 255.),
                deleted: error_red,
                deleted_background: error_red.opacity(26. / 255.),
                deleted_border: error_red.opacity(64. / 255.),
                error: error_red,
                error_background: error_red.opacity(26. / 255.),
                error_border: error_red.opacity(64. / 255.),
                hidden: text_disabled,
                hidden_background: text_disabled.opacity(26. / 255.),
                hidden_border: border_strong,
                hint: text_faint,
                hint_background: focus.opacity(26. / 255.),
                hint_border: border_strong,
                ignored: text_disabled,
                ignored_background: text_disabled.opacity(26. / 255.),
                ignored_border: border,
                info: info_cyan,
                info_background: info_cyan.opacity(26. / 255.),
                info_border: border_strong,
                modified: warning_amber,
                modified_background: warning_amber.opacity(26. / 255.),
                modified_border: warning_amber.opacity(64. / 255.),
                predictive: text_faint,
                predictive_background: text_faint.opacity(26. / 255.),
                predictive_border: border_strong,
                renamed: accent,
                renamed_background: accent.opacity(26. / 255.),
                renamed_border: border_strong,
                success: success_green,
                success_background: success_green.opacity(26. / 255.),
                success_border: success_green.opacity(64. / 255.),
                unreachable: muted,
                unreachable_background: muted.opacity(26. / 255.),
                unreachable_border: border,
                warning: warning_amber,
                warning_background: warning_amber.opacity(26. / 255.),
                warning_border: warning_amber.opacity(64. / 255.),
            },
            player: PlayerColors(vec![
                PlayerColor {
                    cursor: accent,
                    background: accent,
                    selection: accent.opacity(77. / 255.),
                },
                PlayerColor {
                    cursor: red,
                    background: red,
                    selection: red.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: orange,
                    background: orange,
                    selection: orange.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: magenta,
                    background: magenta,
                    selection: magenta.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: cyan,
                    background: cyan,
                    selection: cyan.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: error_red,
                    background: error_red,
                    selection: error_red.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: amber,
                    background: amber,
                    selection: amber.opacity(61. / 255.),
                },
                PlayerColor {
                    cursor: green,
                    background: green,
                    selection: green.opacity(61. / 255.),
                },
            ]),
            syntax: Arc::new(SyntaxTheme::new(vec![
                ("attribute".into(), accent.into()),
                ("boolean".into(), orange.into()),
                ("comment".into(), text_faint.into()),
                ("comment.doc".into(), muted.into()),
                ("constant".into(), amber.into()),
                ("constructor".into(), accent.into()),
                ("embedded".into(), text.into()),
                ("emphasis".into(), accent.into()),
                (
                    "emphasis.strong".into(),
                    HighlightStyle {
                        color: Some(orange),
                        font_weight: Some(FontWeight::BOLD),
                        ..HighlightStyle::default()
                    },
                ),
                ("enum".into(), cyan.into()),
                ("function".into(), accent.into()),
                ("hint".into(), text_faint.into()),
                ("keyword".into(), magenta.into()),
                ("label".into(), accent.into()),
                (
                    "link_text".into(),
                    HighlightStyle {
                        color: Some(accent),
                        font_style: Some(FontStyle::Italic),
                        ..HighlightStyle::default()
                    },
                ),
                ("link_uri".into(), cyan.into()),
                ("namespace".into(), text.into()),
                ("number".into(), orange.into()),
                ("operator".into(), cyan.into()),
                (
                    "predictive".into(),
                    HighlightStyle {
                        color: Some(text_faint),
                        font_style: Some(FontStyle::Italic),
                        ..HighlightStyle::default()
                    },
                ),
                ("preproc".into(), magenta.into()),
                ("primary".into(), muted.into()),
                ("property".into(), red.into()),
                ("punctuation".into(), muted.into()),
                ("punctuation.bracket".into(), muted.into()),
                ("punctuation.delimiter".into(), muted.into()),
                ("punctuation.list_marker".into(), red.into()),
                ("punctuation.markup".into(), red.into()),
                ("punctuation.special".into(), orange.into()),
                ("selector".into(), amber.into()),
                ("selector.pseudo".into(), accent.into()),
                ("string".into(), green.into()),
                ("string.escape".into(), muted.into()),
                ("string.regex".into(), orange.into()),
                ("string.special".into(), orange.into()),
                ("string.special.symbol".into(), orange.into()),
                ("tag".into(), accent.into()),
                ("text.literal".into(), green.into()),
                ("title".into(), red.into()),
                ("type".into(), cyan.into()),
                ("variable".into(), muted.into()),
                ("variable.parameter".into(), red.into()),
                ("variable.special".into(), orange.into()),
                ("variant".into(), accent.into()),
                ("diff.plus".into(), green.into()),
                ("diff.minus".into(), red.into()),
            ])),
        },
    }
}
