'use strict';
// Compagnie aeree e aeroporti per le carte d'imbarco.
// Compagnia dal codice IATA del volo (BCBP): nome e colori del marchio.
// Il logo si scarica da pics.avs.io la prima volta (app.js) e resta in
// memoria sul dispositivo; senza rete si mostra il nome nei colori giusti.
// Aeroporto dal codice IATA: citta' da mostrare sotto il codice.
(function (root) {
  // codice: [nome, colore di fondo, colore del testo]
  const AIRLINES = {
    XZ: ['Aeroitalia', '#1F7A35', '#FFFFFF'],
    AZ: ['ITA Airways', '#0B2E6F', '#FFFFFF'],
    FR: ['Ryanair', '#073590', '#F1C933'],
    RK: ['Ryanair', '#073590', '#F1C933'],
    AL: ['Malta Air', '#073590', '#F1C933'],
    U2: ['easyJet', '#FF6600', '#FFFFFF'],
    EC: ['easyJet', '#FF6600', '#FFFFFF'],
    DS: ['easyJet', '#FF6600', '#FFFFFF'],
    W6: ['Wizz Air', '#C6007E', '#FFFFFF'],
    W4: ['Wizz Air', '#C6007E', '#FFFFFF'],
    W9: ['Wizz Air', '#C6007E', '#FFFFFF'],
    '5W': ['Wizz Air', '#C6007E', '#FFFFFF'],
    V7: ['Volotea', '#2B1A4D', '#FFFFFF'],
    VY: ['Vueling', '#FFCC00', '#2B2B2B'],
    EN: ['Air Dolomiti', '#003C71', '#FFFFFF'],
    NO: ['Neos', '#0D2E5C', '#FFFFFF'],
    LH: ['Lufthansa', '#05164D', '#FFFFFF'],
    LX: ['Swiss', '#E2001A', '#FFFFFF'],
    OS: ['Austrian', '#E30613', '#FFFFFF'],
    SN: ['Brussels Airlines', '#00235F', '#FFFFFF'],
    EW: ['Eurowings', '#A6005C', '#FFFFFF'],
    DE: ['Condor', '#FFCC00', '#2B2B2B'],
    AF: ['Air France', '#002157', '#FFFFFF'],
    KL: ['KLM', '#00A1DE', '#FFFFFF'],
    HV: ['Transavia', '#00D66C', '#13294B'],
    TO: ['Transavia', '#00D66C', '#13294B'],
    BA: ['British Airways', '#075AAA', '#FFFFFF'],
    IB: ['Iberia', '#D7192D', '#FFFFFF'],
    I2: ['Iberia Express', '#D7192D', '#FFFFFF'],
    UX: ['Air Europa', '#0A2A5C', '#FFFFFF'],
    TP: ['TAP Air Portugal', '#E31B23', '#FFFFFF'],
    A3: ['Aegean', '#003B7A', '#FFFFFF'],
    TK: ['Turkish Airlines', '#C90813', '#FFFFFF'],
    PC: ['Pegasus', '#F9B100', '#2B2B2B'],
    LS: ['Jet2', '#E51E2B', '#FFFFFF'],
    BY: ['TUI', '#70CBF4', '#092A5E'],
    X3: ['TUIfly', '#70CBF4', '#092A5E'],
    DY: ['Norwegian', '#D81939', '#FFFFFF'],
    D8: ['Norwegian', '#D81939', '#FFFFFF'],
    SK: ['SAS', '#000F6E', '#FFFFFF'],
    AY: ['Finnair', '#0B1560', '#FFFFFF'],
    LO: ['LOT', '#11397E', '#FFFFFF'],
    BT: ['airBaltic', '#C0D72F', '#1D1D1B'],
    EI: ['Aer Lingus', '#3E8A3A', '#FFFFFF'],
    KM: ['KM Malta Airlines', '#C8102E', '#FFFFFF'],
    OU: ['Croatia Airlines', '#1C3F94', '#FFFFFF'],
    JU: ['Air Serbia', '#1C3F94', '#FFFFFF'],
    RO: ['Tarom', '#0A3A7A', '#FFFFFF'],
    AT: ['Royal Air Maroc', '#C8102E', '#FFFFFF'],
    MS: ['EgyptAir', '#1C2C5B', '#FFFFFF'],
    TU: ['Tunisair', '#E30613', '#FFFFFF'],
    EK: ['Emirates', '#D71920', '#FFFFFF'],
    QR: ['Qatar Airways', '#5C0D34', '#FFFFFF'],
    EY: ['Etihad', '#8C6A2F', '#FFFFFF'],
    DL: ['Delta', '#003366', '#FFFFFF'],
    UA: ['United Airlines', '#005DAA', '#FFFFFF'],
    AA: ['American Airlines', '#0078D2', '#FFFFFF'],
    AC: ['Air Canada', '#D22630', '#FFFFFF'],
    SQ: ['Singapore Airlines', '#02296C', '#FFFFFF'],
    TG: ['Thai Airways', '#4B1E78', '#FFFFFF'],
  };

  // Citta' (nome italiano) per i codici IATA degli aeroporti piu' comuni.
  const AIRPORTS = {
    // Italia
    CTA: 'Catania', PMO: 'Palermo', TPS: 'Trapani', CIY: 'Comiso', REG: 'Reggio Calabria', SUF: 'Lamezia Terme',
    CRV: 'Crotone', NAP: 'Napoli', SAL: 'Salerno', BRI: 'Bari', BDS: 'Brindisi', FOG: 'Foggia', PSR: 'Pescara',
    FCO: 'Roma Fiumicino', CIA: 'Roma Ciampino', FLR: 'Firenze', PSA: 'Pisa', BLQ: 'Bologna', FRL: 'Forlì',
    RMI: 'Rimini', AOI: 'Ancona', PEG: 'Perugia', VCE: 'Venezia', TSF: 'Treviso', VRN: 'Verona', TRS: 'Trieste',
    BZO: 'Bolzano', MXP: 'Milano Malpensa', LIN: 'Milano Linate', BGY: 'Bergamo', TRN: 'Torino', CUF: 'Cuneo',
    GOA: 'Genova', PMF: 'Parma', CAG: 'Cagliari', OLB: 'Olbia', AHO: 'Alghero', LMP: 'Lampedusa', PNL: 'Pantelleria',
    // Europa
    LHR: 'Londra Heathrow', LGW: 'Londra Gatwick', STN: 'Londra Stansted', LTN: 'Londra Luton', LCY: 'Londra City',
    MAN: 'Manchester', EDI: 'Edimburgo', DUB: 'Dublino', CDG: 'Parigi CDG', ORY: 'Parigi Orly', BVA: 'Parigi Beauvais',
    NCE: 'Nizza', MRS: 'Marsiglia', LYS: 'Lione', TLS: 'Tolosa', BOD: 'Bordeaux', NTE: 'Nantes',
    AMS: 'Amsterdam', EIN: 'Eindhoven', BRU: 'Bruxelles', CRL: 'Charleroi', LUX: 'Lussemburgo',
    FRA: 'Francoforte', HHN: 'Francoforte Hahn', MUC: 'Monaco di Baviera', BER: 'Berlino', HAM: 'Amburgo',
    DUS: 'Düsseldorf', CGN: 'Colonia', STR: 'Stoccarda', NUE: 'Norimberga', MMX: 'Malmö', ZRH: 'Zurigo',
    GVA: 'Ginevra', BSL: 'Basilea', VIE: 'Vienna', SZG: 'Salisburgo', PRG: 'Praga', BUD: 'Budapest',
    WAW: 'Varsavia', WMI: 'Varsavia Modlin', KRK: 'Cracovia', GDN: 'Danzica', OTP: 'Bucarest', CLJ: 'Cluj',
    SOF: 'Sofia', BEG: 'Belgrado', ZAG: 'Zagabria', SPU: 'Spalato', DBV: 'Dubrovnik', LJU: 'Lubiana',
    TIA: 'Tirana', SKP: 'Skopje', ATH: 'Atene', SKG: 'Salonicco', HER: 'Heraklion', CFU: 'Corfù', RHO: 'Rodi',
    JTR: 'Santorini', JMK: 'Mykonos', MLA: 'Malta', LCA: 'Larnaca', PFO: 'Paphos', IST: 'Istanbul',
    SAW: 'Istanbul Sabiha', AYT: 'Antalya', MAD: 'Madrid', BCN: 'Barcellona', VLC: 'Valencia', AGP: 'Malaga',
    ALC: 'Alicante', SVQ: 'Siviglia', PMI: 'Palma di Maiorca', IBZ: 'Ibiza', MAH: 'Minorca', BIO: 'Bilbao',
    TFS: 'Tenerife Sud', TFN: 'Tenerife Nord', LPA: 'Gran Canaria', ACE: 'Lanzarote', FUE: 'Fuerteventura',
    LIS: 'Lisbona', OPO: 'Porto', FAO: 'Faro', CPH: 'Copenaghen', ARN: 'Stoccolma', OSL: 'Oslo', HEL: 'Helsinki',
    RIX: 'Riga', VNO: 'Vilnius', TLL: 'Tallinn', KEF: 'Reykjavík',
    // Fuori Europa
    TUN: 'Tunisi', CMN: 'Casablanca', RAK: 'Marrakech', CAI: 'Il Cairo', SSH: 'Sharm el-Sheikh', HRG: 'Hurghada',
    TLV: 'Tel Aviv', DXB: 'Dubai', AUH: 'Abu Dhabi', DOH: 'Doha', JFK: 'New York JFK', EWR: 'New York Newark',
    BOS: 'Boston', MIA: 'Miami', ORD: 'Chicago', LAX: 'Los Angeles', SFO: 'San Francisco', YYZ: 'Toronto',
    YUL: 'Montréal', GRU: 'San Paolo', EZE: 'Buenos Aires', BKK: 'Bangkok', SIN: 'Singapore', HND: 'Tokyo Haneda',
    NRT: 'Tokyo Narita', PEK: 'Pechino', HKG: 'Hong Kong', DEL: 'Delhi', MLE: 'Malé', ZNZ: 'Zanzibar',
  };

  function airline(code) {
    const c = String(code || '').trim().toUpperCase();
    const a = AIRLINES[c];
    return a ? { code: c, name: a[0], color: a[1], text: a[2] } : null;
  }
  const city = (code) => AIRPORTS[String(code || '').trim().toUpperCase()] || '';

  const api = { airline, city, AIRLINES, AIRPORTS };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.MementoAirlines = api;
})(typeof window !== 'undefined' ? window : globalThis);
