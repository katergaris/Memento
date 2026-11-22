'use strict';
// Compagnie aeree e aeroporti per le carte d'imbarco.
// Compagnia dal codice IATA del volo (BCBP): nome e colori del marchio.
// Il logo si scarica da pics.avs.io la prima volta (app.js) e resta in
// memoria sul dispositivo; senza rete si mostra il nome nei colori giusti.
// Aeroporto dal codice IATA: citta' e nome dell'aeroporto sotto il codice.
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

  // Aeroporto dal codice IATA: [citta' (in italiano), nome dell'aeroporto].
  const AIRPORTS = {
    // Italia
    CTA: ['Catania', 'Fontanarossa'], PMO: ['Palermo', 'Falcone e Borsellino'], TPS: ['Trapani', 'Birgi'],
    CIY: ['Comiso', 'Pio La Torre'], REG: ['Reggio Calabria', 'Tito Minniti'], SUF: ['Lamezia Terme', 'Aeroporto internazionale'],
    CRV: ['Crotone', 'Sant\'Anna'], NAP: ['Napoli', 'Capodichino'], SAL: ['Salerno', 'Costa d\'Amalfi'],
    BRI: ['Bari', 'Karol Wojtyła'], BDS: ['Brindisi', 'Papola Casale'], FOG: ['Foggia', 'Gino Lisa'],
    PSR: ['Pescara', 'Abruzzo'], FCO: ['Roma', 'Fiumicino'], CIA: ['Roma', 'Ciampino'],
    FLR: ['Firenze', 'Peretola'], PSA: ['Pisa', 'Galileo Galilei'], BLQ: ['Bologna', 'Guglielmo Marconi'],
    FRL: ['Forlì', 'Luigi Ridolfi'], RMI: ['Rimini', 'Federico Fellini'], AOI: ['Ancona', 'Falconara'],
    PEG: ['Perugia', 'San Francesco d\'Assisi'], VCE: ['Venezia', 'Marco Polo'], TSF: ['Treviso', 'Antonio Canova'],
    VRN: ['Verona', 'Villafranca'], TRS: ['Trieste', 'Ronchi dei Legionari'], BZO: ['Bolzano', 'Aeroporto di Bolzano'],
    MXP: ['Milano', 'Malpensa'], LIN: ['Milano', 'Linate'], BGY: ['Bergamo', 'Orio al Serio'],
    TRN: ['Torino', 'Caselle'], CUF: ['Cuneo', 'Levaldigi'], GOA: ['Genova', 'Cristoforo Colombo'],
    PMF: ['Parma', 'Giuseppe Verdi'], CAG: ['Cagliari', 'Elmas'], OLB: ['Olbia', 'Costa Smeralda'],
    AHO: ['Alghero', 'Fertilia'], LMP: ['Lampedusa', 'Aeroporto di Lampedusa'], PNL: ['Pantelleria', 'Aeroporto di Pantelleria'],
    // Europa
    LHR: ['Londra', 'Heathrow'], LGW: ['Londra', 'Gatwick'], STN: ['Londra', 'Stansted'], LTN: ['Londra', 'Luton'],
    LCY: ['Londra', 'London City'], MAN: ['Manchester', 'Aeroporto di Manchester'], EDI: ['Edimburgo', 'Aeroporto di Edimburgo'],
    DUB: ['Dublino', 'Aeroporto di Dublino'], CDG: ['Parigi', 'Charles de Gaulle'], ORY: ['Parigi', 'Orly'],
    BVA: ['Parigi', 'Beauvais-Tillé'], NCE: ['Nizza', 'Costa Azzurra'], MRS: ['Marsiglia', 'Provenza'],
    LYS: ['Lione', 'Saint-Exupéry'], TLS: ['Tolosa', 'Blagnac'], BOD: ['Bordeaux', 'Mérignac'], NTE: ['Nantes', 'Atlantique'],
    AMS: ['Amsterdam', 'Schiphol'], EIN: ['Eindhoven', 'Aeroporto di Eindhoven'], BRU: ['Bruxelles', 'Zaventem'],
    CRL: ['Bruxelles', 'Charleroi'], LUX: ['Lussemburgo', 'Findel'], FRA: ['Francoforte', 'Aeroporto di Francoforte'],
    HHN: ['Francoforte', 'Hahn'], MUC: ['Monaco di Baviera', 'Franz Josef Strauss'], BER: ['Berlino', 'Willy Brandt'],
    HAM: ['Amburgo', 'Helmut Schmidt'], DUS: ['Düsseldorf', 'Aeroporto di Düsseldorf'], CGN: ['Colonia', 'Colonia-Bonn'],
    STR: ['Stoccarda', 'Aeroporto di Stoccarda'], NUE: ['Norimberga', 'Albrecht Dürer'], MMX: ['Malmö', 'Sturup'],
    ZRH: ['Zurigo', 'Kloten'], GVA: ['Ginevra', 'Cointrin'], BSL: ['Basilea', 'EuroAirport'],
    VIE: ['Vienna', 'Schwechat'], SZG: ['Salisburgo', 'W. A. Mozart'], PRG: ['Praga', 'Václav Havel'],
    BUD: ['Budapest', 'Ferenc Liszt'], WAW: ['Varsavia', 'Chopin'], WMI: ['Varsavia', 'Modlin'],
    KRK: ['Cracovia', 'Giovanni Paolo II'], GDN: ['Danzica', 'Lech Wałęsa'], OTP: ['Bucarest', 'Henri Coandă'],
    CLJ: ['Cluj-Napoca', 'Avram Iancu'], SOF: ['Sofia', 'Aeroporto di Sofia'], BEG: ['Belgrado', 'Nikola Tesla'],
    ZAG: ['Zagabria', 'Franjo Tuđman'], SPU: ['Spalato', 'Aeroporto di Spalato'], DBV: ['Dubrovnik', 'Čilipi'],
    LJU: ['Lubiana', 'Jože Pučnik'], TIA: ['Tirana', 'Madre Teresa'], SKP: ['Skopje', 'Aeroporto internazionale'],
    ATH: ['Atene', 'Eleftherios Venizelos'], SKG: ['Salonicco', 'Macedonia'], HER: ['Heraklion', 'Nikos Kazantzakis'],
    CFU: ['Corfù', 'Ioannis Kapodistrias'], RHO: ['Rodi', 'Diagoras'], JTR: ['Santorini', 'Thira'], JMK: ['Mykonos', 'Aeroporto di Mykonos'],
    MLA: ['Malta', 'Luqa'], LCA: ['Larnaca', 'Aeroporto internazionale'], PFO: ['Paphos', 'Aeroporto internazionale'],
    IST: ['Istanbul', 'Aeroporto di Istanbul'], SAW: ['Istanbul', 'Sabiha Gökçen'], AYT: ['Antalya', 'Aeroporto di Antalya'],
    MAD: ['Madrid', 'Barajas'], BCN: ['Barcellona', 'El Prat'], VLC: ['Valencia', 'Manises'],
    AGP: ['Malaga', 'Costa del Sol'], ALC: ['Alicante', 'Elche'], SVQ: ['Siviglia', 'San Pablo'],
    PMI: ['Palma di Maiorca', 'Son Sant Joan'], IBZ: ['Ibiza', 'Aeroporto di Ibiza'], MAH: ['Minorca', 'Mahón'],
    BIO: ['Bilbao', 'Loiu'], TFS: ['Tenerife', 'Tenerife Sud'], TFN: ['Tenerife', 'Tenerife Nord'],
    LPA: ['Gran Canaria', 'Gando'], ACE: ['Lanzarote', 'César Manrique'], FUE: ['Fuerteventura', 'Aeroporto di Fuerteventura'],
    LIS: ['Lisbona', 'Humberto Delgado'], OPO: ['Porto', 'Francisco Sá Carneiro'], FAO: ['Faro', 'Aeroporto di Faro'],
    CPH: ['Copenaghen', 'Kastrup'], ARN: ['Stoccolma', 'Arlanda'], OSL: ['Oslo', 'Gardermoen'], HEL: ['Helsinki', 'Vantaa'],
    RIX: ['Riga', 'Aeroporto internazionale'], VNO: ['Vilnius', 'Aeroporto internazionale'], TLL: ['Tallinn', 'Lennart Meri'],
    KEF: ['Reykjavík', 'Keflavík'],
    // Fuori Europa
    TUN: ['Tunisi', 'Cartagine'], CMN: ['Casablanca', 'Mohammed V'], RAK: ['Marrakech', 'Menara'], CAI: ['Il Cairo', 'Aeroporto internazionale'],
    SSH: ['Sharm el-Sheikh', 'Aeroporto internazionale'], HRG: ['Hurghada', 'Aeroporto internazionale'], TLV: ['Tel Aviv', 'Ben Gurion'],
    DXB: ['Dubai', 'Aeroporto internazionale'], AUH: ['Abu Dhabi', 'Zayed'], DOH: ['Doha', 'Hamad'],
    JFK: ['New York', 'John F. Kennedy'], EWR: ['New York', 'Newark Liberty'], BOS: ['Boston', 'Logan'], MIA: ['Miami', 'Aeroporto internazionale'],
    ORD: ['Chicago', 'O\'Hare'], LAX: ['Los Angeles', 'Aeroporto internazionale'], SFO: ['San Francisco', 'Aeroporto internazionale'],
    YYZ: ['Toronto', 'Pearson'], YUL: ['Montréal', 'Pierre Elliott Trudeau'], GRU: ['San Paolo', 'Guarulhos'], EZE: ['Buenos Aires', 'Ezeiza'],
    BKK: ['Bangkok', 'Suvarnabhumi'], SIN: ['Singapore', 'Changi'], HND: ['Tokyo', 'Haneda'], NRT: ['Tokyo', 'Narita'],
    PEK: ['Pechino', 'Capitale'], HKG: ['Hong Kong', 'Aeroporto internazionale'], DEL: ['Delhi', 'Indira Gandhi'],
    MLE: ['Malé', 'Velana'], ZNZ: ['Zanzibar', 'Abeid Amani Karume'],
  };

  function airline(code) {
    const c = String(code || '').trim().toUpperCase();
    const a = AIRLINES[c];
    return a ? { code: c, name: a[0], color: a[1], text: a[2] } : null;
  }
  const ap = (code) => AIRPORTS[String(code || '').trim().toUpperCase()] || null;
  const city = (code) => (ap(code) || [''])[0];
  // Nome dell'aeroporto; vuoto se e' solo "Aeroporto di <citta'>".
  const airportName = (code) => { const a = ap(code); return a && !/^Aeroporto di /.test(a[1]) ? a[1] : ''; };

  const api = { airline, city, airportName, AIRLINES, AIRPORTS };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.MementoAirlines = api;
})(typeof window !== 'undefined' ? window : globalThis);
