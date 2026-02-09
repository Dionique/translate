# QA-raportti

1) Extraction gate
- FAIL: Poimittu teksti sisältää epäjohdonmaisen §-numeroinnin ja rakenteen, joten rakenteellinen eheys ei ole luotettava. Tämän vuoksi käännöstä ei tehty.
- Vaikutus: useita lukuja/§-kohtia, rakenteellinen järjestys epävarma.

2) Completeness
- Chapters: NOT OK (Finnish 12, Russian 0)
- §§: NOT OK (Finnish 110, Russian 0)
- Missing/at-risk sections: kaikki §-kohdat (1–106)

3) Structural integrity
- Lists preserved: NOT OK (käännöstä ei ole)
- Collapse rule violations: kaikki §-kohdat (1–106)
- Paragraph differences: merkittäviä (käännöstä ei ole)

4) Semantic fidelity
- Overall judgement: FAIL
- FATAL issues: kaikki §-kohdat (käännös puuttuu)
- Residual ambiguities: n/a

5) Terminology consistency
- Locked glossary mapping (planned, not applied due to no translation):
  - toimilupa → лицензия
  - yksinoikeustoimilupa → лицензия исключительного права
  - rahapelitoimilupa → лицензия на организацию азартных игр
  - peliohjelmistotoimilupa → лицензия на программное обеспечение игр
  - rahapelitoiminta → деятельность по организации азартных игр
  - rahapelihaitta → вред от азартных игр
- Lexical synonym drift: n/a

6) Artefacts
- Artefact scan: ISSUES (rakenteelliset epäjohdonmukaisuudet poimitussa tekstissä)
- Affected sections: useita §-kohtia (ei yksilöitävissä luotettavasti poiminnan epävarmuuden vuoksi)

7) Overall score
- Score: 2/10
- Justification: PDF-poiminta tuotti epäjohdonmukaisen rakenteen, minkä vuoksi luotettava käännös ei ollut mahdollinen. Toimitetut tiedostot sisältävät parhaaksi arvioidun suomalaisen lähdetekstin, mutta käännös puuttuu. Suositus on täydentää poiminta (esim. OCR) ja toistaa prosessi ennen käyttöä.
- Fit-for-purpose recommendation: internal reading only
