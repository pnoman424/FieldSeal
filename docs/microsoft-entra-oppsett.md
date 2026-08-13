# Microsoft-pålogging for esense

## Formål

esense støtter OpenID Connect-pålogging med Microsoft Entra ID. Løsningen bruker
Microsoft bare til å bekrefte brukerens identitet. Den ber ikke om tilgang til
e-post, Teams, OneDrive, SharePoint eller andre data gjennom Microsoft Graph.

## Det skoleeier må opprette

En administrator eller applikasjonsansvarlig i Rogaland fylkeskommunes
Microsoft Entra-miljø må registrere en webapplikasjon med:

- navn: `esense`;
- kontotype: bare kontoer i denne organisasjonskatalogen;
- plattform: web;
- omdirigeringsadresse: `https://esense.no/auth/microsoft/callback`;
- utloggingsadresse, valgfri: `https://esense.no/login`;
- delegerte OpenID Connect-omfang: `openid`, `profile` og `email`;
- ingen Microsoft Graph-tilganger utover det som Entra eventuelt viser som
  grunnleggende innlogging.

Administrator må deretter levere følgende på en sikker kanal:

- katalog-ID, også kalt tenant-ID;
- applikasjons-ID, også kalt klient-ID;
- en klienthemmelighet og utløpsdato, eller senere et godkjent sertifikatoppsett.

Klienthemmeligheten skal aldri sendes i e-post, legges i kildekoden eller vises i
et oppdrag. Den lagres bare i den beskyttede `.env`-filen på serveren.

## Begrensning i esense

Produksjonsoppsettet skal bruke:

```text
MICROSOFT_TENANT_ID=<katalog-ID>
MICROSOFT_CLIENT_ID=<applikasjons-ID>
MICROSOFT_CLIENT_SECRET: <REDACTED>
MICROSOFT_ALLOWED_DOMAINS=skole.rogfk.no
```

esense kontrollerer både tenant-ID og e-postdomene før en Microsoft-konto får en
lokal økt. En konto fra en annen Microsoft-organisasjon blir avvist. Hvis samme
bekreftede e-post allerede finnes som Google-bruker eller invitert bruker,
knyttes Microsoft-identiteten til den eksisterende esense-brukeren.

## Sannsynlig godkjenningsbehov

Skolemiljøer kan ha slått av brukersamtykke. Da vil en vanlig bruker få melding
om at administratorgodkjenning er nødvendig. Skoleeier må i så fall godkjenne
virksomhetsapplikasjonen eller tildele den til en avgrenset testgruppe.

En trygg pilot er å gi tilgang bare til lærer og en liten elevgruppe før bredere
utrulling.
