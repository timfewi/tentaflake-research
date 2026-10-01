//! Coherent browser profile selection from an observed VPN exit region.
//!
//! A profile fixes locale, IANA timezone and Accept-Language together so the
//! browser never presents mutually contradictory signals (for example a `de-DE`
//! locale with a `UTC` clock or an `en-US` Accept-Language). Selection happens
//! when a session is created; a running session keeps its profile even if the
//! exit region later changes. The tool never chooses or changes the VPN exit and
//! promises no anonymity: it only adapts to the exit the trusted lease reports.

use crate::config::ProfilePolicy;
use crate::error::{ErrorCode, Result};
use serde::{Deserialize, Serialize};

/// Locale, timezone and Accept-Language fixed together for one browser session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub locale: String,
    pub timezone: String,
    pub accept_language: String,
}

impl Profile {
    /// The default, internally coherent profile used when no region is known or
    /// the operator keeps rotation disabled.
    pub fn neutral() -> Self {
        Self {
            locale: "en-US".into(),
            timezone: "UTC".into(),
            accept_language: "en-US,en;q=0.9".into(),
        }
    }

    /// Return a coherent profile for an ISO 3166-1 alpha-2 exit region, or
    /// `None` when the region is not in the bounded table.
    ///
    /// The table is deliberately finite and hand-reviewed: every entry uses the
    /// region's own language, a real IANA timezone located in that country and
    /// an Accept-Language whose primary tag matches the locale. It is sorted by
    /// region code. Extending it requires an explicit review, not a runtime
    /// guess; an unknown region falls back to [`Profile::neutral`] in
    /// [`Profile::resolve`] rather than fabricating a combination.
    pub fn for_region(region: &str) -> Option<Self> {
        let (locale, timezone, accept_language) = match region {
            "AT" => ("de-AT", "Europe/Vienna", "de-AT,de;q=0.9,en;q=0.8"),
            "AU" => ("en-AU", "Australia/Sydney", "en-AU,en;q=0.9"),
            "BE" => ("nl-BE", "Europe/Brussels", "nl-BE,nl;q=0.9,en;q=0.8"),
            "BR" => ("pt-BR", "America/Sao_Paulo", "pt-BR,pt;q=0.9,en;q=0.8"),
            "CA" => ("en-CA", "America/Toronto", "en-CA,en;q=0.9,fr;q=0.8"),
            "CH" => ("de-CH", "Europe/Zurich", "de-CH,de;q=0.9,en;q=0.8"),
            "CZ" => ("cs-CZ", "Europe/Prague", "cs-CZ,cs;q=0.9,en;q=0.8"),
            "DE" => ("de-DE", "Europe/Berlin", "de-DE,de;q=0.9,en;q=0.8"),
            "DK" => ("da-DK", "Europe/Copenhagen", "da-DK,da;q=0.9,en;q=0.8"),
            "ES" => ("es-ES", "Europe/Madrid", "es-ES,es;q=0.9,en;q=0.8"),
            "FI" => ("fi-FI", "Europe/Helsinki", "fi-FI,fi;q=0.9,en;q=0.8"),
            "FR" => ("fr-FR", "Europe/Paris", "fr-FR,fr;q=0.9,en;q=0.8"),
            "GB" => ("en-GB", "Europe/London", "en-GB,en;q=0.9"),
            "IE" => ("en-IE", "Europe/Dublin", "en-IE,en;q=0.9"),
            "IN" => ("en-IN", "Asia/Kolkata", "en-IN,en;q=0.9,hi;q=0.8"),
            "IT" => ("it-IT", "Europe/Rome", "it-IT,it;q=0.9,en;q=0.8"),
            "JP" => ("ja-JP", "Asia/Tokyo", "ja-JP,ja;q=0.9,en;q=0.8"),
            "KR" => ("ko-KR", "Asia/Seoul", "ko-KR,ko;q=0.9,en;q=0.8"),
            "MX" => ("es-MX", "America/Mexico_City", "es-MX,es;q=0.9,en;q=0.8"),
            "NL" => ("nl-NL", "Europe/Amsterdam", "nl-NL,nl;q=0.9,en;q=0.8"),
            "NO" => ("nb-NO", "Europe/Oslo", "nb-NO,nb;q=0.9,en;q=0.8"),
            "PL" => ("pl-PL", "Europe/Warsaw", "pl-PL,pl;q=0.9,en;q=0.8"),
            "PT" => ("pt-PT", "Europe/Lisbon", "pt-PT,pt;q=0.9,en;q=0.8"),
            "SE" => ("sv-SE", "Europe/Stockholm", "sv-SE,sv;q=0.9,en;q=0.8"),
            "SG" => ("en-SG", "Asia/Singapore", "en-SG,en;q=0.9"),
            "US" => ("en-US", "America/New_York", "en-US,en;q=0.9"),
            "ZA" => ("en-ZA", "Africa/Johannesburg", "en-ZA,en;q=0.9"),
            _ => return None,
        };
        Some(Self {
            locale: locale.into(),
            timezone: timezone.into(),
            accept_language: accept_language.into(),
        })
    }

    /// Choose the profile for one session from operator policy and the observed
    /// exit region. `ExitRegion` falls back to [`Profile::neutral`] when the
    /// region is absent or unknown; the fallback is itself coherent.
    pub fn resolve(policy: ProfilePolicy, region: Option<&str>) -> Self {
        match policy {
            ProfilePolicy::Neutral => Self::neutral(),
            ProfilePolicy::ExitRegion => region
                .and_then(Self::for_region)
                .unwrap_or_else(Self::neutral),
        }
    }

    /// Reject strings outside the small charset and length budget the browser
    /// launch and CDP overrides accept. This guards a caller-supplied profile;
    /// table and neutral profiles always pass.
    pub fn validate(&self) -> Result<()> {
        if !charset(&self.locale, b"-", 16)
            || !charset(&self.timezone, b"/_+-", 64)
            || !charset(&self.accept_language, b",;=. -", 128)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

fn charset(value: &str, allowed: &[u8], maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || allowed.contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The full bounded region set. A change to the table must be reviewed here.
    const REGIONS: [&str; 27] = [
        "AT", "AU", "BE", "BR", "CA", "CH", "CZ", "DE", "DK", "ES", "FI", "FR", "GB", "IE", "IN",
        "IT", "JP", "KR", "MX", "NL", "NO", "PL", "PT", "SE", "SG", "US", "ZA",
    ];

    #[test]
    fn neutral_profile_is_coherent_and_valid() {
        let neutral = Profile::neutral();
        assert_eq!(neutral.locale, "en-US");
        assert_eq!(neutral.timezone, "UTC");
        assert_eq!(neutral.accept_language, "en-US,en;q=0.9");
        neutral.validate().unwrap();
    }

    #[test]
    fn german_region_maps_to_a_coherent_profile() {
        let profile = Profile::for_region("DE").unwrap();
        assert_eq!(profile.locale, "de-DE");
        assert_eq!(profile.timezone, "Europe/Berlin");
        assert_eq!(profile.accept_language, "de-DE,de;q=0.9,en;q=0.8");
        profile.validate().unwrap();
        assert!(profile.accept_language.starts_with(&profile.locale));
    }

    #[test]
    fn every_table_entry_is_coherent_and_sorted() {
        let mut previous = None;
        for region in REGIONS {
            let profile = Profile::for_region(region).unwrap_or_else(|| {
                panic!("missing region {region}");
            });
            profile.validate().unwrap();
            // Locale primary tag is language-REGION and matches the requested
            // region; Accept-Language leads with that same locale.
            assert!(
                profile.locale.ends_with(&format!("-{region}")),
                "{region} locale {} does not end in -{region}",
                profile.locale
            );
            assert!(
                profile.accept_language.starts_with(&profile.locale),
                "{region} Accept-Language {} does not lead with locale {}",
                profile.accept_language,
                profile.locale
            );
            assert!(
                profile.timezone.contains('/'),
                "{region} timezone {} is not a region-qualified IANA zone",
                profile.timezone
            );
            assert!(
                previous.is_none_or(|name| name < region),
                "table not sorted"
            );
            previous = Some(region);
        }
        // Unknown, empty and malformed regions are absent from the table.
        for unknown in ["ZZ", "", "de", "DEU", "EU", "US\n"] {
            assert!(Profile::for_region(unknown).is_none(), "{unknown}");
        }
    }

    #[test]
    fn resolve_falls_back_to_neutral_for_unknown_or_absent_region() {
        let neutral = Profile::neutral();
        assert_eq!(
            Profile::resolve(ProfilePolicy::Neutral, Some("DE")),
            neutral
        );
        assert_eq!(Profile::resolve(ProfilePolicy::ExitRegion, None), neutral);
        assert_eq!(
            Profile::resolve(ProfilePolicy::ExitRegion, Some("ZZ")),
            neutral
        );
        assert_eq!(
            Profile::resolve(ProfilePolicy::ExitRegion, Some("DE")),
            Profile::for_region("DE").unwrap()
        );
    }

    #[test]
    fn invalid_strings_are_rejected() {
        let locale = Profile {
            locale: "en/us".into(),
            ..Profile::neutral()
        };
        let empty_locale = Profile {
            locale: String::new(),
            ..Profile::neutral()
        };
        let long_locale = Profile {
            locale: "a".repeat(17),
            ..Profile::neutral()
        };
        let bad_timezone = Profile {
            timezone: "Europe Berlin".into(),
            ..Profile::neutral()
        };
        let long_timezone = Profile {
            timezone: "a".repeat(65),
            ..Profile::neutral()
        };
        let bad_language = Profile {
            accept_language: "en-US\n".into(),
            ..Profile::neutral()
        };
        let long_language = Profile {
            accept_language: "a".repeat(129),
            ..Profile::neutral()
        };
        for invalid in [
            locale,
            empty_locale,
            long_locale,
            bad_timezone,
            long_timezone,
            bad_language,
            long_language,
        ] {
            assert_eq!(invalid.validate().unwrap_err(), ErrorCode::InvalidRequest);
        }
    }
}
