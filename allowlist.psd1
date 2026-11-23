@{
    # =====================================================================
    #  Suppression rules for Invoke-WinTriage.ps1
    #
    #  A rule moves a finding out of the results and into the report's
    #  "suppressed" section, which states the reason, who accepted it and
    #  until when. Nothing is ever hidden silently.
    #
    #  A rule needs at least Key, Title or Evidence. Category alone is
    #  refused on purpose: it would silence a whole check.
    #
    #    Key       the 12-character identifier printed under each finding
    #              (and exported by the report's "Export my decisions")
    #    Category  check key: Activators, Drivers, Browsers, ...
    #    Title     regex matched against the English title
    #    Evidence  regex matched against the English evidence block
    #    Reason    why this is accepted - write it for your future self
    #    Author    who decided
    #    Expires   yyyy-MM-dd. Past that date the rule stops applying and
    #              the report says so, so acceptances get revisited.
    #
    #  The report's export button produces ready-to-paste Key entries.
    # =====================================================================

    Suppress = @(
        # @{ Key = 'a1b2c3d4e5f6'; Reason = 'ASRock monitoring driver, shipped with the motherboard utility'
        #    Author = 'you@example.com'; Expires = '2027-01-31' }
        #
        # @{ Category = 'Browsers'; Title = 'extension with powerful permissions.*FoxyProxy'
        #    Reason = 'Proxy switcher installed by the user on purpose'
        #    Author = 'you@example.com'; Expires = '2027-06-30' }
        #
        # @{ Category = 'RemoteAccess'; Title = 'Remote access tool present: teamviewer'
        #    Reason = 'Used by the helpdesk, ticket INC-1234'
        #    Author = 'you@example.com'; Expires = '2027-03-01' }
    )
}
