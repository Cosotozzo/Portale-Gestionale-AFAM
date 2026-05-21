// =========================================================================
// CONFIGURAZIONE ARCHITETTURALE ENTERPRISE - PORTALE GESTIONALE AFAM
// =========================================================================

const props = PropertiesService.getScriptProperties();

/**
 * ROUTER DI AMBIENTE: Rileva automaticamente se il link è /dev (Sviluppo)
 * o /exec (Produzione) e seleziona i database corretti dal "Vault".
 */
function getEnvironmentConfig() {
  let isDevEnv = false;
  try {
    const url = ScriptApp.getService().getUrl();
    // Se l'URL contiene '/dev' o se siamo nell'editor, attiviamo la Sandbox
    if (!url || url.indexOf('/dev') !== -1) {
      isDevEnv = true;
    }
  } catch (e) {
    isDevEnv = true; 
  }

  // Costruisce il suffisso dinamico (_TEST o _PROD)
  const suffix = isDevEnv ? '_TEST' : '_PROD';
  
  // LOG di sicurezza visibile solo negli screenshot/debug dell'editor
  console.log(`[SISTEMA AFAM] Boot in modalità: ${isDevEnv ? 'SANDBOX' : 'PRODUZIONE'}`);

  return {
    MASTER_ID: props.getProperty('ID_MASTER' + suffix),
    ID_BUDGETORGANICO: props.getProperty('ID_BUDGETORGANICO' + suffix),
    ID_CESSAZIONI: props.getProperty('ID_CESSAZIONI' + suffix)
  };
}

// Inizializzazione Ambiente (Caricato una sola volta per esecuzione)
const CURRENT_ENV = getEnvironmentConfig();

/**
 * CONFIGURAZIONE DATABASE E FOGLI
 * Centralizza tutti gli ID e i nomi dei fogli per l'intero portale.
 */
var DB_CONFIG = {
  // Database IDs (Dinamici)
  "MASTER_ID": CURRENT_ENV.MASTER_ID,
  "ID_BUDGETORGANICO": CURRENT_ENV.ID_BUDGETORGANICO,
  "ID_CESSAZIONI": CURRENT_ENV.ID_CESSAZIONI,
  
  // Nomi Fogli Master
  "SHEET_ISTITUZIONI": "ISTITUZIONI",
  "SHEET_ANAGRAFICA": "ANAGRAFICA_UTENTI",
  "SHEET_CREDENZIALI": "CREDENZIALI_ACCESSO",
  
  // Nomi Fogli Cessazioni
  "SHEET_CESSAZIONI_ANAG": "ANAGRAFICA_CESSAZIONI",
  "SHEET_CESSAZIONI_RESP": "RISPOSTE_ISTITUZIONI",
  "SHEET_CESSAZIONI_EXP": "EXPORT_DATI_CESSAZIONI",
  
  // Nomi Fogli Budget
  "SHEET_BUDGET_BASE": "BUDGET_BASE",
  "SHEET_BUDGET_TRANS": "BUDGET_TRANS",
  "SHEET_BUDGET_EXP": "BUDGET_EXP"
};

/**
 * MAPPA DELLE COLONNE (COL_MAP) - Base 0
 * Fondamentale per leggere i dati da array JavaScript (getValues())
 */
const COL_MAP = {
  CRED: {
    ID: 0, CF: 1, ISTITUZIONE_ID: 2, NOME: 3, COGNOME: 4, USERNAME: 5,
    HASH: 6, SALT: 7, RUOLO: 8, PIN: 9, STATO: 11, SESSION_ID: 14, 
    LAST_LOGIN: 15, ACCETTAZIONE_PRIVACY: 16, ACCETTAZIONE_COOKIE: 17
  },
  ANAG_CESS: {
    ID_CESSAZIONE: 0, ID_ISTITUZIONE: 1, NOME: 3, COGNOME: 4, CF: 5, QUALIFICA: 6
  },
  ANAG_UTENTI: {
    ID_ISTITUZIONE: 0, CF: 1, NOME: 2, COGNOME: 3, RUOLO: 4
  },
  BUDGET_BASE: {
    ID_ISTITUZIONE: 0, DENOMINAZIONE: 1, BUDGET_INIZIALE: 2
  },
  BUDGET_TRANS: {
    ID_TRANS: 0, ID_RICHIEDENTE: 1, ID_CEDENTE: 2, STATO: 3, JSON_BLOB: 4
  }, 
  BUDGET_EXP: {
    ID_CEDENTE: 0, DENOM_CEDENTE: 1, RESIDUO_ANTE_CED: 2, RESIDUO_POST_CED: 3,
    ID_ACQUIRENTE: 4, DENOM_ACQUIRENTE: 5, RESIDUO_ANTE_ACQ: 6, RESIDUO_POST_ACQ: 7, 
    VALORE_SCAMB: 8, ID_TRANS: 9
  }
};

// --- FUNZIONI DI SISTEMA E UTILITY ---

function doGet() {
  return HtmlService.createTemplateFromFile('Index')
    .evaluate()
    .setTitle('Portale Gestione AFAM - MUR')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

function formatDateSafe(raw) {
  if (!raw) return "";
  try {
    if (raw instanceof Date) {
      return ("0" + raw.getDate()).slice(-2) + "/" + ("0" + (raw.getMonth() + 1)).slice(-2) + "/" + raw.getFullYear();
    }
    return String(raw).trim();
  } catch (e) { return ""; }
}

function hashPassword(password, salt) {
  var rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password + salt, Utilities.Charset.UTF_8);
  var txtHash = '';
  for (var i = 0; i < rawHash.length; i++) {
    var hashVal = rawHash[i];
    if (hashVal < 0) hashVal += 256;
    if (hashVal.toString(16).length == 1) txtHash += '0';
    txtHash += hashVal.toString(16);
  }
  return txtHash;
}

function generateUUID() { return Utilities.getUuid(); }

/**
 * Funzione globale di sanitizzazione contro Formula/CSV Injection (CWE-1236).
 * Neutralizza i caratteri operativi forzando la cella a comportarsi come testo puro.
 */
function sanitizeForFormulaInjection(input) {
  if (input === null || input === undefined) return "";
  let str = String(input);
  if (/^[=+\-@]/.test(str)) {
    str = "'" + str; 
  }
  return str;
}

/**
 * Sanitizzazione avanzata nella deserializzazione del JSON per i payload del Budget.
 * Garantisce un'architettura rigorosa e previene Null Pointer o Type Errors.
 * @param {string} rawStr - La stringa JSON estratta dal database.
 * @returns {Object} - L'oggetto payload fortemente tipizzato e sanitizzato.
 */
function parseBudgetPayload(rawStr) {
    const defaultPayload = {
        importo_richiesto: 0,
        conferma_delibera: false,
        history: [],
        note: ""
    };
    
    try {
        if (!rawStr) return defaultPayload;
        
        const obj = JSON.parse(rawStr);
        
        // Validazione strutturale esplicita: deve essere un oggetto e non un array
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
            return defaultPayload;
        }
        
        // Type casting esplicito preventivo
        return {
            importo_richiesto: parseFloat(obj.importo_richiesto) || 0,
            conferma_delibera: Boolean(obj.conferma_delibera),
            history: Array.isArray(obj.history) ? obj.history : [],
            note: obj.note ? String(obj.note).substring(0, 1000) : "" // Previene DoS
        };
    } catch (e) {
        Logger.log("[SECURITY ALERT] Fallimento parsing JSON Budget. Payload corrotto: " + e.message);
        return defaultPayload; // Fallback difensivo in caso di Parsing Error
    }
}

/**
 * Verifica se il modulo Scambio Budget è attivo tramite ScriptProperties.
 * Approccio Zero Trust: se fallisce, nega l'accesso di default.
 */
function isScambioBudgetAttivo() {
  try {
    Logger.log("[MASTER SWITCH] Lettura stato Scambio Budget.");
    var props = PropertiesService.getScriptProperties();
    var status = props.getProperty('SCAMBIO_BUDGET_ATTIVO');
    return status === 'TRUE';
  } catch(e) {
    Logger.log("[ERRORE] ScriptProperties irraggiungibili: " + e.message);
    return false; // Fail-safe: modulo chiuso in caso di errore
  }
}

/**
 * CORE: GESTIONE SESSIONE (SICUREZZA ZERO TRUST & PERFORMANCE)
 * Risolve CWE-843 (Type Confusion) ed evita l'appropriazione di identità di utenti offline.
 */
function verifySessionAndGetUser(token) {
  // 1. VALIDAZIONE ZERO TRUST STRUTTURALE (Strict Type Checking)
  if (!token || typeof token !== 'string' || token.trim().length === 0) {
    throw new Error("Sessione non valida. Token mancante o formato compromesso. Accesso negato.");
  }
  
  const cleanToken = token.trim();

  // 2. PROVA A LEGGERE DALLA CACHE VELOCE
  const cache = CacheService.getScriptCache();
  const cachedUser = cache.get("SESSION_" + cleanToken);
  if (cachedUser) {
    return JSON.parse(cachedUser);
  }

  // 3. FALLBACK: SE NON IN CACHE, USA TEXTFINDER (VELOCE)
  const ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
  const sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
  
  const finder = sheetCred.getRange(1, COL_MAP.CRED.SESSION_ID + 1, sheetCred.getLastRow(), 1)
                          .createTextFinder(cleanToken)
                          .matchEntireCell(true);
  const result = finder.findNext();
  
  if (result) {
    const rowIndex = result.getRow();
    const rowData = sheetCred.getRange(rowIndex, 1, 1, sheetCred.getLastColumn()).getValues()[0];
    
    // 4. VERIFICA SECONDARIA ZERO TRUST (Integrità del Dato)
    const dbToken = String(rowData[COL_MAP.CRED.SESSION_ID]).trim();
    if (dbToken !== cleanToken || cleanToken === "") {
      throw new Error("Integrità sessione compromessa. Tentativo di bypass rilevato.");
    }

    if (rowData[COL_MAP.CRED.STATO] !== 'ATTIVO') throw new Error("Utenza disabilitata o non autorizzata.");
    
    try { 
      sheetCred.getRange(rowIndex, COL_MAP.CRED.LAST_LOGIN + 1).setValue(new Date());
    } catch(e){}

    const userObj = {
      rowIndex: rowIndex,
      username: rowData[COL_MAP.CRED.USERNAME],
      istituzioneId: rowData[COL_MAP.CRED.ISTITUZIONE_ID],
      ruolo: rowData[COL_MAP.CRED.RUOLO],
      nome: rowData[COL_MAP.CRED.NOME],
      cognome: rowData[COL_MAP.CRED.COGNOME],
      privacyLog: rowData[COL_MAP.CRED.ACCETTAZIONE_PRIVACY],
      cookieLog: rowData[COL_MAP.CRED.ACCETTAZIONE_COOKIE]
    };
    
    // 5. SALVA IN CACHE PER 20 MINUTI
    cache.put("SESSION_" + cleanToken, JSON.stringify(userObj), 1200);
    return userObj;
  }
  
  throw new Error("Sessione scaduta o invalida.");
}

/**
 * Tenta di ripristinare la sessione utente dato un token.
 * Usato dal frontend al refresh (F5) della pagina.
 */
function restoreSession(token) {
  try {
    // Riutilizziamo la logica centrale di verifica (Zero Trust)
    // Questo aggiorna anche il timestamp di ultimo accesso (heartbeat)
    var userCtx = verifySessionAndGetUser(token);
    
    // Ricostruiamo l'oggetto utente per il frontend
return {
      success: true,
      token: token,
      username: userCtx.username,
      role: userCtx.ruolo,
      nome: userCtx.nome,
      cognome: userCtx.cognome,
      istituzioneId: userCtx.istituzioneId,
      istituzioneNome: getInstitutionNameById(userCtx.istituzioneId),
      privacyAccepted: String(userCtx.privacyLog || "").includes("ACCETTATO"),
      cookieAccepted: String(userCtx.cookieLog || "").includes("ACCETTATO")
    };
  } catch (e) {
    // Se la sessione è scaduta o invalida, il frontend dovrà fare logout
    return { success: false, message: e.message };
  }
}

// --- LOGIN ---

/**
 * Gestisce l'autenticazione utente con protezione per accessi simultanei massivi.
 * @param {Object} formObject Oggetto contenente username e password dal client.
 */
function doLogin(formObject) {
  try {
    var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
    var data = sheetCred.getDataRange().getValues();
    var usernameInput = String(formObject.username).trim();
    var passwordInput = formObject.password;

    var targetRowIndex = -1;
    var targetUser = null;

    // 1. Ricerca iper-veloce con TextFinder (Cerca solo nella colonna USERNAME, indice F = 6)
    var searchRange = sheetCred.getRange(1, COL_MAP.CRED.USERNAME + 1, sheetCred.getLastRow(), 1);
    var finder = searchRange.createTextFinder(usernameInput).matchEntireCell(true);
    var result = finder.findNext();

    if (result) {
      targetRowIndex = result.getRow();
      // Leggiamo IN MEMORIA SOLO la riga interessata (molto più leggero di getDataRange)
      targetUser = sheetCred.getRange(targetRowIndex, 1, 1, sheetCred.getLastColumn()).getValues()[0];
      
      var storedHash = targetUser[COL_MAP.CRED.HASH];
      var salt = targetUser[COL_MAP.CRED.SALT];

      if (hashPassword(passwordInput, salt) === storedHash) {
        const statoUtenza = targetUser[COL_MAP.CRED.STATO];
        if (statoUtenza !== 'ATTIVO') {
          if (statoUtenza === 'RIFIUTATO') {
            return { success: false, message: "La richiesta di attivazione per l'utenza è stata rifiutata dal Ministero." };
          }
          return { success: false, message: "Utenza in attesa di approvazione da parte del Ministero." };
        }
      } else { 
        return { success: false, message: "Nome Utente o Password errata." };
      }
    } else {
       return { success: false, message: "Utente non trovato." };
    }

    var newSessionId = generateUUID();

    // 2. Acquisizione del Lock SOLO per la scrittura
    var lock = LockService.getScriptLock();
try {
      // Aumentato il timeout a 30s per supportare picchi > 100 accessi simultanei
      lock.waitLock(30000); 
      
      // Batch I/O Ottimizzato: Le colonne SESSION_ID e LAST_LOGIN sono contigue.
      // Uniamo le due scritture in un'unica chiamata setValues per dimezzare il tempo di locking
      sheetCred.getRange(targetRowIndex, COL_MAP.CRED.SESSION_ID + 1, 1, 2)
               .setValues([[newSessionId, new Date()]]);
               
      // La formattazione può essere applicata senza spezzare l'array
      sheetCred.getRange(targetRowIndex, COL_MAP.CRED.LAST_LOGIN + 1)
               .setNumberFormat("dd/MM/yyyy HH:mm:ss");

      SpreadsheetApp.flush(); // Fondamentale prima del rilascio
    } finally {
      lock.releaseLock();
    }

return {
      success: true, 
      token: newSessionId, 
      username: usernameInput,
      role: targetUser[COL_MAP.CRED.RUOLO], 
      nome: targetUser[COL_MAP.CRED.NOME], 
      cognome: targetUser[COL_MAP.CRED.COGNOME], 
      istituzioneId: targetUser[COL_MAP.CRED.ISTITUZIONE_ID],
      istituzioneNome: getInstitutionNameById(targetUser[COL_MAP.CRED.ISTITUZIONE_ID]),
      privacyAccepted: String(targetUser[COL_MAP.CRED.ACCETTAZIONE_PRIVACY] || "").includes("ACCETTATO"),
      cookieAccepted: String(targetUser[COL_MAP.CRED.ACCETTAZIONE_COOKIE] || "").includes("ACCETTATO")
    };

  } catch (e) {
    Logger.log("ERRORE CRITICO LOGIN: " + e.message);
    return { 
      success: false, 
      message: "Il server è al momento sovraccarico. Riprova tra pochi istanti."
    };
  }
}

// --- CESSAZIONI ---

function fetchCessazioniForUser(token) {
  try {
    var userCtx = verifySessionAndGetUser(token);
    // Normalizziamo il ruolo per evitare errori di case-sensitivity
    var ruolo = String(userCtx.ruolo).toUpperCase().trim();

    // --- LOGICA DISPATCHER: SOLO ADMIN E MINISTERO VEDONO IL REPORT ---
    if (ruolo === 'ADMIN' || ruolo === 'MINISTERO') {
       return generateAdminReport();
    }
    // ------------------------------------------------------------------

    var idIstituzione = String(userCtx.istituzioneId).trim();
    
    // --- INIZIO LOGICA STANDARD ISTITUZIONE ---
    // Recupero Denominazione Istituzione
var cache = CacheService.getScriptCache();
    var denominazioneUfficiale = "Istituzione";
    
    // 1. Recupero Istituzioni da Cache o DB
    var cachedIst = cache.get("CACHE_ISTITUZIONI_MAP");
    if (cachedIst) {
        var mapIst = JSON.parse(cachedIst);
        denominazioneUfficiale = mapIst[idIstituzione] || "Istituzione";
    } else {
        var ssAuth = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
        var sheetIst = ssAuth.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
        var dataIst = sheetIst.getDataRange().getValues();
        var tempMap = {};
        for(var k=1; k<dataIst.length; k++) {
            tempMap[String(dataIst[k][0]).trim()] = dataIst[k][1];
            if(String(dataIst[k][0]).trim() === idIstituzione) denominazioneUfficiale = dataIst[k][1];
        }
        cache.put("CACHE_ISTITUZIONI_MAP", JSON.stringify(tempMap), 21600); // 6 ore
    }

    var ssCess = SpreadsheetApp.openById(DB_CONFIG.ID_CESSAZIONI);
    
    var today = new Date();
    var currentYear = today.getFullYear();
    var academicYear = (today.getMonth() > 8) ?
        currentYear + "/" + (currentYear + 1) : (currentYear - 1) + "/" + currentYear;

    // 2. Recupero Anagrafica filtrata (Da Cache o DB)
    var listaSoggetti = [];
    var cacheKeyAnag = "CACHE_ANAG_" + idIstituzione;
    var cachedAnag = cache.get(cacheKeyAnag);
    
    if (cachedAnag) {
        listaSoggetti = JSON.parse(cachedAnag);
    } else {
        var sheetAnag = ssCess.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_ANAG);
        if (!sheetAnag || sheetAnag.getLastRow() < 2) {
            return { success: true, listaSoggetti: [], statoModulo: 'NON_COMPILATO', denominazione: denominazioneUfficiale, aa: academicYear, richiestaNuovaFinestra: false };
        }
        var dataAnag = sheetAnag.getDataRange().getValues(); 
        for(var i=1; i<dataAnag.length; i++) {
          if(!dataAnag[i][0]) continue;
          if(String(dataAnag[i][COL_MAP.ANAG_CESS.ID_ISTITUZIONE]).trim() === idIstituzione) {
            var qualificaRaw = dataAnag[i][COL_MAP.ANAG_CESS.QUALIFICA];
            var qualificaStr = qualificaRaw ? String(qualificaRaw).trim() : "N/D"; 

            listaSoggetti.push({
              idCessazione: String(dataAnag[i][COL_MAP.ANAG_CESS.ID_CESSAZIONE]),
              cf: String(dataAnag[i][COL_MAP.ANAG_CESS.CF]).toUpperCase().trim(),
              nome: String(dataAnag[i][COL_MAP.ANAG_CESS.NOME]),
              cognome: String(dataAnag[i][COL_MAP.ANAG_CESS.COGNOME]),
              qualifica: qualificaStr,
              azione: null, note: ""
            });
          }
        }
        cache.put(cacheKeyAnag, JSON.stringify(listaSoggetti), 1800); // 30 Minuti di cache
    }
    
    // Recupero Dati Salvati (Risposte)
    var sheetResp = ssCess.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_RESP);
    var statoModulo = 'NON_COMPILATO';
    var dataInvio = null;
    var jsonDettaglio = [];
    var richiestaNuovaFinestra = false;

    if (sheetResp && sheetResp.getLastRow() > 1) {
      var dataResp = sheetResp.getDataRange().getValues();
      var lastDateFound = 0;
      
      for(var i=1; i<dataResp.length; i++) {
        // Filtro per ID Istituzione
        if(String(dataResp[i][1]).trim() === idIstituzione) {
          var currentDate = new Date(dataResp[i][3]).getTime();
          if (currentDate > lastDateFound) {
             lastDateFound = currentDate;
             statoModulo = dataResp[i][2];
             dataInvio = formatDateSafe(dataResp[i][3]);
             try { 
               var rawJson = dataResp[i][5];
               if(rawJson && rawJson !== "") {
                   var parsed = JSON.parse(rawJson);
                   if(Array.isArray(parsed)){
                     jsonDettaglio = parsed;
                     richiestaNuovaFinestra = false;
                   } else {
                     jsonDettaglio = parsed.rows || [];
                     richiestaNuovaFinestra = parsed.flag === true; 
                   }
               }
             } catch(e) { jsonDettaglio = []; }
          }
        }
      }
    }
    
    // Merge
    if(jsonDettaglio.length > 0) {
      listaSoggetti.forEach(function(sogg) {
        var saved = jsonDettaglio.find(function(item) { return item.cf === sogg.cf; });
        if(saved) { sogg.azione = saved.azione; sogg.note = saved.note; }
      });
    }
    
    return {
      success: true, 
      listaSoggetti: listaSoggetti, 
      statoModulo: statoModulo,
      dataInvio: dataInvio, 
      denominazione: denominazioneUfficiale, 
      aa: academicYear,
      richiestaNuovaFinestra: richiestaNuovaFinestra
    };

  } catch (error) {
    return { success: false, message: "Errore Backend: " + error.message };
  }
}

/**
 * Genera il report aggregato per ADMIN e MINISTERO
 * Incrocia ISTITUZIONI (Anagrafica) con RISPOSTE (Stati e JSON)
 */
function generateAdminReport() {
  try {
    var ssAuth = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    var sheetIst = ssAuth.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
    var listIst = sheetIst.getDataRange().getValues(); // [ID, Nome, ...]

    var ssCess = SpreadsheetApp.openById(DB_CONFIG.ID_CESSAZIONI);
    var sheetResp = ssCess.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_RESP);
    
    // Gestione caso foglio vuoto
    var listResp = (sheetResp && sheetResp.getLastRow() > 1) 
                   ? sheetResp.getDataRange().getValues() 
                   : []; 

    // 1. Mappa Risposte per accesso rapido (ID_IST -> {stato, json, data})
    // Prendiamo sempre l'ultimo invio valido
    var mapResp = {};
    for (var r = 1; r < listResp.length; r++) {
       var idIst = String(listResp[r][1]).trim(); // Col B
       // Sovrascriviamo, assumendo che l'ordine cronologico o l'ultimo sia quello buono 
       // (Oppure si può implementare logica di data maggiore, qui semplificato last-wins per ID)
       // NOTA: Se ci sono più righe per istituzione, idealmente prendiamo quella con data più recente.
       // Implementiamo controllo data base:
       var currentDate = new Date(listResp[r][3]).getTime();
       
       if (!mapResp[idIst] || currentDate > mapResp[idIst].timestamp) {
           mapResp[idIst] = {
             stato: listResp[r][2], // Col C
             dataInvio: listResp[r][3], // Col D
             json: listResp[r][5], // Col F
             timestamp: currentDate
           };
       }
    }

    // 2. Costruzione Report
    var report = [];
    
    // Ciclo su TUTTE le istituzioni (anche quelle che non hanno compilato)
    // i=1 per saltare header
    for (var i = 1; i < listIst.length; i++) {
       var idIst = String(listIst[i][0]).trim();
       var nomeIst = listIst[i][1];
       
       // Oggetto base
       var rowData = {
         id: idIst,
         denominazione: nomeIst,
         stato: 'NON_COMPILATO',
         totale: 0,
         approvati: 0,
         modificati: 0,
         rifiutati: 0,
         pendenti: 0,
         nuovaFinestra: false
       };

       if (mapResp[idIst]) {
         var resp = mapResp[idIst];
         rowData.stato = resp.stato;
         
         // Parsing JSON e Calcolo Statistiche
         try {
           if (resp.json && resp.json !== "") {
             var parsed = JSON.parse(resp.json);
             var rows = Array.isArray(parsed) ? parsed : (parsed.rows || []);
             var flag = Array.isArray(parsed) ? false : (parsed.flag === true);
             
             rowData.nuovaFinestra = flag;
             rowData.totale = rows.length;
             
             rows.forEach(function(r) {
               if (r.azione === 'APPROVA') rowData.approvati++;
               else if (r.azione === 'MODIFICA') rowData.modificati++;
               else if (r.azione === 'RIFIUTA') rowData.rifiutati++;
               else rowData.pendenti++;
             });
           }
         } catch (e) {
           // JSON non valido o vuoto
         }
       }
       report.push(rowData);
    }
    
    // Ordina alfabeticamente per nome istituzione
    report.sort(function(a, b) { 
        return String(a.denominazione).localeCompare(String(b.denominazione)); 
    });

    return {
      success: true,
      isAdmin: true, // Flag fondamentale per il Frontend
      reportData: report
    };

  } catch(e) {
    Logger.log("Err Admin Report: " + e.message);
    return { success: false, message: "Errore generazione report: " + e.message };
  }
}

/**
 * VERSIONE OTTIMIZZATA (SOLO SALVATAGGIO)
 * Gestisce l'alta concorrenza (100+ utenti) usando TextFinder e Upsert.
 * Rimuove il collo di bottiglia dell'Export (spostato alla notte).
 */
function saveCessazioni(token, payload) {
  const tStart = new Date().getTime(); 
  
  try {
    // 1. VALIDAZIONE ZERO TRUST (Eseguita fuori dalla sezione critica)
    const userCtx = verifySessionAndGetUser(token);
    const idIstituzione = String(userCtx.istituzioneId);
    
    if (!payload || !payload.rows || !Array.isArray(payload.rows)) {
      throw new Error("Formato dati non valido.");
    }

    // Sanitizzazione e validazione profonda del payload
    const cleanRows = payload.rows.map(row => {
      // Regola di business: Note obbligatorie per MODIFICA
      if (payload.mode === 'FINAL' && row.azione === 'MODIFICA' && (!row.note || row.note.trim().length < 3)) {
        throw new Error(`Errore validazione: Inserire una nota valida per il CF ${row.cf}.`);
      }
      
      return {
        idCessazione: String(row.idCessazione || "").trim(),
        cf: String(row.cf || "").toUpperCase().trim(),
        azione: row.azione ? String(row.azione).trim() : null,
        note: row.note ? String(row.note).trim() : ""
      };
    });

    const nuovoStato = (payload.mode === 'FINAL') ? 'INVIATO' : 'BOZZA';
    const dataOperazione = new Date();
    const dataBlob = {
      rows: cleanRows,
      flag: payload.richiestaNuovaFinestra === true
    };
    const jsonString = JSON.stringify(dataBlob);

    // 2. SEZIONE CRITICA (LOCKING OTTIMIZZATO)
    const lock = LockService.getScriptLock();
    const hasLock = lock.tryLock(30000); // Timeout 30s per gestire code massive
    
    if (!hasLock) throw new Error("Il server è momentaneamente occupato. Riprovare tra qualche secondo.");
    
    try {
      const ss = SpreadsheetApp.openById(DB_CONFIG.ID_CESSAZIONI);
      const sheetResp = ss.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_RESP);
      
// Ottimizzazione della geometria di ricerca
      const lastRowIndex = Math.max(sheetResp.getLastRow(), 1);
      // Confina la ricerca alle sole righe effettivamente popolate (Colonna 2 = B)
      const searchRange = sheetResp.getRange(1, 2, lastRowIndex, 1);
      const finder = searchRange.createTextFinder(idIstituzione).matchEntireCell(true);
      const result = finder.findNext();
      
      if (result) {
        // Update riga esistente: Col 3 (Stato), 4 (Data), 5 (Utente), 6 (JSON)
        const rowIdx = result.getRow();
        sheetResp.getRange(rowIdx, 3, 1, 4).setValues([[nuovoStato, dataOperazione, userCtx.username, jsonString]]);
      } else {
        // Insert nuova riga
        const newId = Utilities.getUuid();
        sheetResp.appendRow([newId, idIstituzione, nuovoStato, dataOperazione, userCtx.username, jsonString]);
      }
      
      SpreadsheetApp.flush();
      Logger.log(`[AUDIT] Save Success | User: ${userCtx.username} | Mode: ${payload.mode} | Time: ${new Date().getTime() - tStart}ms`);
      
    } finally {
      lock.releaseLock();
    }
    
    return { 
      success: true, 
      message: (payload.mode === 'FINAL') ? "Invio completato e protocollato." : "Bozza salvata correttamente.",
      lastSave: Utilities.formatDate(dataOperazione, "Europe/Rome", "dd/MM/yyyy HH:mm:ss")
    };

  } catch (e) {
    Logger.log(`[ERROR] Save Failed | Reason: ${e.message}`);
    return { success: false, message: e.message };
  }
}

// --- UTILS REGISTRAZIONE & ADMIN ---

function getInstitutionNames() {
  var cache = CacheService.getScriptCache();
  var cachedData = cache.get("INSTITUTION_LIST");

  if (cachedData != null) {
    // Return da Cache (velocissimo)
    return JSON.parse(cachedData);
  }

  // Fallback: Lettura da DB (lento)
  var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
  var sheet = ss.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
  var lastRow = sheet.getLastRow();
  
  if (lastRow < 2) return [];
  
  var data = sheet.getRange(2, 2, lastRow - 1, 1).getValues();
  var cleanList = data.flat().filter(String).sort();

  // Salvataggio in Cache per 6 ore (21600 secondi)
  cache.put("INSTITUTION_LIST", JSON.stringify(cleanList), 21600);
  
  return cleanList;
}

/**
 * Utility: Recupera la denominazione dell'istituzione dato il suo ID usando la cache.
 */
function getInstitutionNameById(id) {
    if (!id) return "";
    var cache = CacheService.getScriptCache();
    var cachedIst = cache.get("CACHE_ISTITUZIONI_MAP");
    var mapIst = {};
    if (cachedIst) {
        mapIst = JSON.parse(cachedIst);
    } else {
        var ssAuth = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
        var sheetIst = ssAuth.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
        if (sheetIst) {
            var dataIst = sheetIst.getDataRange().getValues();
            for(var k=1; k<dataIst.length; k++) {
                mapIst[String(dataIst[k][0]).trim()] = dataIst[k][1];
            }
            // Cache per 6 ore
            cache.put("CACHE_ISTITUZIONI_MAP", JSON.stringify(mapIst), 21600);
        }
    }
    return mapIst[String(id).trim()] || id;
}

// INIZIO MODIFICA - FUNZIONI ADMIN UTENZE
function fetchPendingUsers(token) {
  try {
    var userCtx = verifySessionAndGetUser(token);
    if (String(userCtx.ruolo).toUpperCase() !== 'ADMIN') throw new Error("Accesso negato: Funzione riservata agli amministratori.");

    var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    
    // Mappa Istituzioni per display amichevole
    var sheetIst = ss.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
    var dataIst = sheetIst.getDataRange().getValues();
    var mapIst = {};
    for(var k=1; k<dataIst.length; k++) mapIst[dataIst[k][0]] = dataIst[k][1];

    var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
    var data = sheetCred.getDataRange().getValues();
    var pending = [];

    for (var i = 1; i < data.length; i++) {
       // Check Stato (Colonna 11 da COL_MAP)
       if (data[i][COL_MAP.CRED.STATO] === 'IN_ATTESA_DI_APPROVAZIONE') {
           var iId = data[i][COL_MAP.CRED.ISTITUZIONE_ID];
           pending.push({
               id: data[i][COL_MAP.CRED.ID],
               nome: data[i][COL_MAP.CRED.NOME],
               cognome: data[i][COL_MAP.CRED.COGNOME],
               cf: data[i][COL_MAP.CRED.CF],
               email: data[i][COL_MAP.CRED.USERNAME],
               istituzione: mapIst[iId] || iId,
               dataRichiesta: formatDateSafe(data[i][12]) // Timestamp creazione (Col 12)
           });
       }
    }
    return { success: true, users: pending };
  } catch(e) { return { success: false, message: e.message }; }
}

function updateUserStatus(token, userId, action) {
  // 1. VALIDAZIONE ZERO TRUST (Fuori dal Lock)
  var userCtx = verifySessionAndGetUser(token);
  if (String(userCtx.ruolo).toUpperCase() !== 'ADMIN') throw new Error("Non autorizzato.");
  
  var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
  var sheet = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
  
  // 2. SEZIONE CRITICA OTTIMIZZATA
  var lock = LockService.getScriptLock();
  try {
      lock.waitLock(10000); // L'attesa masisma si saturerà raramente adesso
      
      // O(1) Lookup con TextFinder invece di getDataRange() sotto lock
      var searchRange = sheet.getRange(1, COL_MAP.CRED.ID + 1, sheet.getLastRow(), 1);
      var finder = searchRange.createTextFinder(String(userId)).matchEntireCell(true);
      var result = finder.findNext();
      
      if(!result) throw new Error("Utente non trovato.");
      
      var newState = (action === 'APPROVE') ? 'ATTIVO' : 'RIFIUTATO';
      sheet.getRange(result.getRow(), COL_MAP.CRED.STATO + 1).setValue(newState);
      
      SpreadsheetApp.flush();
      return { success: true, message: "Stato utente aggiornato a: " + (action === 'APPROVE' ? 'ATTIVO' : 'RIFIUTATO') };
  } catch(e) {
      return { success: false, message: "Errore: " + e.message };
  } finally {
      lock.releaseLock();
  }
}

function registerUser(formObject) {
  try {
    var pin = String(formObject.pin).trim().toUpperCase();
    if (!pin || pin.length !== 6) return { success: false, message: "Il PIN deve essere di 6 caratteri." };
    var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    var sheetIst = ss.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
    var dataIst = sheetIst.getDataRange().getValues();
    var foundIdIstituzione = null;
    var inputInstName = String(formObject.institutionName).trim().toLowerCase();
    for (var i = 1; i < dataIst.length; i++) { 
        if (String(dataIst[i][1]).trim().toLowerCase() === inputInstName) { 
            foundIdIstituzione = dataIst[i][0];
            break; 
        } 
    }
    if (!foundIdIstituzione) return { success: false, message: "Istituzione non trovata." };

    var sheetAnag = ss.getSheetByName(DB_CONFIG.SHEET_ANAGRAFICA);
    var dataAnag = sheetAnag.getDataRange().getValues();
    var userWhitelist = null;
    var inputCF = String(formObject.codiceFiscale).toUpperCase().replace(/\s+/g, ''); // Rimuove spazi interni al CF
    // Normalizziamo rimuovendo spazi doppi
    var inputNome = String(formObject.nome).toUpperCase().trim().replace(/\s+/g, ' '); 
    var inputCognome = String(formObject.cognome).toUpperCase().trim().replace(/\s+/g, ' ');
    
for (var i = 1; i < dataAnag.length; i++) {
      // Check sul CF usando la mappatura corretta
      if (String(dataAnag[i][COL_MAP.ANAG_UTENTI.ID_ISTITUZIONE]) === String(foundIdIstituzione) && 
          String(dataAnag[i][COL_MAP.ANAG_UTENTI.CF]).toUpperCase().trim().replace(/\s+/g, '') === inputCF) {
        
        const dbNome = String(dataAnag[i][COL_MAP.ANAG_UTENTI.NOME]).toUpperCase().trim().replace(/\s+/g, ' ');
        const dbCognome = String(dataAnag[i][COL_MAP.ANAG_UTENTI.COGNOME]).toUpperCase().trim().replace(/\s+/g, ' ');
        
        // Confronto flessibile: true se il database contiene l'input (es. db: "Mario Antonio", input: "Mario") o viceversa
        const nameMatch = dbNome.includes(inputNome) || inputNome.includes(dbNome);
        const surnameMatch = dbCognome.includes(inputCognome) || inputCognome.includes(dbCognome);

        if (!nameMatch || !surnameMatch) {
            Logger.log(`Mismatch Anagrafica: DB[${dbNome} ${dbCognome}] vs INPUT[${inputNome} ${inputCognome}]`);
            return { success: false, message: `Il Nominativo inserito non corrisponde all'anagrafica (${dbNome} ${dbCognome}).` };
        }
        
        userWhitelist = { 
            idIstituzione: String(dataAnag[i][COL_MAP.ANAG_UTENTI.ID_ISTITUZIONE]), 
            cf: inputCF, 
            nome: dataAnag[i][COL_MAP.ANAG_UTENTI.NOME], 
            cognome: dataAnag[i][COL_MAP.ANAG_UTENTI.COGNOME], 
            ruolo: dataAnag[i][COL_MAP.ANAG_UTENTI.RUOLO] 
        };
        break;
      }
    }
    if (!userWhitelist) return { success: false, message: "Dati non trovati nell'anagrafica autorizzata per questa istituzione." };

    var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
    var dataCred = sheetCred.getDataRange().getValues();
    var inputEmail = String(formObject.email).trim().toLowerCase();

    for (var i = 1; i < dataCred.length; i++) { 
        // Controllo 1: Codice Fiscale già presente
        if (String(dataCred[i][COL_MAP.CRED.CF]).toUpperCase() === userWhitelist.cf) {
            return { success: false, message: "Utente (Codice Fiscale) già registrato." }; 
        }
        // Controllo 2: Email già presente
        if (String(dataCred[i][COL_MAP.CRED.USERNAME]).trim().toLowerCase() === inputEmail) {
            return { success: false, message: "Indirizzo email già presente nel sistema. Usa un'altra email o recupera la password." }; 
        }
    }
    
// Validazione robusta lato server sulla complessità della password (Zero Trust)
    var passwordInput = String(formObject.password || "");
    const REGEX_STRONG_SERVER = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!REGEX_STRONG_SERVER.test(passwordInput)) {
        return { success: false, message: "La password non soddisfa i requisiti di complessità e sicurezza." };
    }

    var salt = generateUUID();
    var passwordHash = hashPassword(formObject.password, salt);
// Formattiamo la data del momento esatto per il tracciato DB
    var timestampConsenso = Utilities.formatDate(new Date(), "Europe/Rome", "dd/MM/yyyy HH:mm:ss");
    var privacyLog = formObject.privacyConsent ? "ACCETTATO - " + timestampConsenso : "NON ACCETTATO";
    var cookieLog = formObject.cookieConsent ? "ACCETTATO - " + timestampConsenso : "NON ACCETTATO";

// Costruzione del payload con protezione Zero Trust (CWE-1236) su tutti i campi
    const rowData = [
        generateUUID(), 
        userWhitelist.cf, 
        userWhitelist.idIstituzione, 
        userWhitelist.nome, 
        userWhitelist.cognome, 
        String(formObject.email).trim(), 
        passwordHash, 
        salt, 
        userWhitelist.ruolo, 
        pin, 
        '', 
        'IN_ATTESA_DI_APPROVAZIONE', 
        new Date(), 
        '', '', '', 
        privacyLog, 
        cookieLog
    ].map(val => (typeof val === 'string') ? sanitizeForFormulaInjection(val) : val);

    // Salvataggio: Mappiamo Privacy su Colonna Q (17) e Cookie su Colonna R (18)
    sheetCred.appendRow(rowData);
    return { success: true, message: "Registrazione inviata. Attendi approvazione." };
  } catch(e) { return { success: false, message: "Errore: " + e.message }; }
}

function resetPasswordByData(formObj) {
  try {
    var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    var sheetIst = ss.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
    var dataIst = sheetIst.getDataRange().getValues();
    var targetIdIst = null;
    var searchName = String(formObj.institutionName).trim().toLowerCase();
    
    // 1. Ricerca ID Istituzione
    for (var i = 1; i < dataIst.length; i++) { 
        if (String(dataIst[i][1]).trim().toLowerCase() === searchName) { 
            targetIdIst = dataIst[i][0];
            break; 
        } 
    }
    
    if (!targetIdIst) return { success: false, message: "Istituzione non trovata." };

    // --- INIZIO MODIFICA: Logica di ricerca utente ottimizzata e Zero Trust ---
    var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
    var dataCred = sheetCred.getDataRange().getValues();
    var userRowIndex = -1;
    
    // Normalizzazione preventiva degli input utente
    var inputUsernameSearch = String(formObj.username).trim().toLowerCase();
    var inputCfSearch = String(formObj.cf).trim().toUpperCase();
    var inputTargetIdIst = String(targetIdIst).trim();
    var inputPin = String(formObj.pin).trim().toUpperCase();

    // 2. Ricerca utente nel DB Credenziali
    for (var i = 1; i < dataCred.length; i++) {
      var row = dataCred[i];
      
      // Estrazione e normalizzazione dei dati riga per riga
      var dbCf = String(row[COL_MAP.CRED.CF]).trim().toUpperCase();
      var dbIdIst = String(row[COL_MAP.CRED.ISTITUZIONE_ID]).trim();
      var dbUsername = String(row[COL_MAP.CRED.USERNAME]).trim().toLowerCase();
      
      // Matching di Sicurezza
      if (dbCf === inputCfSearch && dbIdIst === inputTargetIdIst && dbUsername === inputUsernameSearch) { 
          
          var storedPin = String(row[COL_MAP.CRED.PIN]).trim().toUpperCase();
          if (storedPin !== inputPin) { 
            return { success: false, message: "PIN di sicurezza errato." }; 
          }
          
          userRowIndex = i + 1; 
          break;
      }
    }
    // --- FINE MODIFICA ---

// 3. Verifica esito e reset password
    if (userRowIndex === -1) {
        return { success: false, message: "Dati utente non trovati."
        };
    }
    
    // Validazione robusta lato server sulla complessità della password (Zero Trust)
    var passwordInput = String(formObj.newPassword || "");
    const REGEX_STRONG_SERVER = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!REGEX_STRONG_SERVER.test(passwordInput)) {
        return { success: false, message: "La nuova password non soddisfa i requisiti di complessità e sicurezza." };
    }
    
    var newSalt = generateUUID();
    var newHash = hashPassword(formObj.newPassword, newSalt);
    
    var lock = LockService.getScriptLock();
    try {
        lock.waitLock(10000); // Attesa max 10 secondi
        
        sheetCred.getRange(userRowIndex, COL_MAP.CRED.HASH + 1).setValue(newHash);
        sheetCred.getRange(userRowIndex, COL_MAP.CRED.SALT + 1).setValue(newSalt);
        
        SpreadsheetApp.flush(); // Forza l'applicazione immediata delle scritture
    } finally {
        lock.releaseLock(); // Rilascio garantito
    }
    
    return { success: true, message: "Password aggiornata con successo." };
    
  } catch(e) { 
    return { success: false, message: "Errore: " + e.toString() };
  }
}

function logoutUser(token) {
  try {
    // 1. RIMUOVI DALLA CACHE (Operazione Veloce)
    // È fondamentale usare la stessa chiave usata nel login ("SESSION_" + token)
    var cache = CacheService.getScriptCache();
    cache.remove("SESSION_" + token); 

    // 2. RIMUOVI DAL DB (Operazione Lenta ma Persistente)
    var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
    var data = sheetCred.getDataRange().getValues();
    
    for (var i = 1; i < data.length; i++) {
      // Cerca la riga corrispondente al token
      if (String(data[i][COL_MAP.CRED.SESSION_ID]) === token) {
        // Cancella il token dalla cella
        sheetCred.getRange(i + 1, COL_MAP.CRED.SESSION_ID + 1).setValue("");
        return true;
      }
    }
  } catch(e) {
    // Log dell'errore ma non blocchiamo l'utente
    Logger.log("Errore durante logout: " + e.message);
    return false;
  }
}

/**
 * TRIGGER NOTTURNO CESSAZIONI reso strettamente privato.
 * L'aggiunta dell'underscore finale impedisce fisicamente a google.script.run 
 * di risolvere e mappare l'endpoint, bloccando l'esecuzione anonima.
 */
function syncExportTable_() {
  const lock = LockService.getScriptLock();
  try { 
    // Timeout ridotto drasticamente a 5 secondi per i job in background.
    // Previene stalli irreversibili della coda di esecuzione in caso di conflitti.
    if (!lock.tryLock(5000)) {
      Logger.log(" Tentativo di sync interrotto: Lock di sistema occupato.");
      return; 
    }
  } catch(e) { 
    return; 
  } 
  
  try {
    const ss = SpreadsheetApp.openById(DB_CONFIG.ID_CESSAZIONI);
    const sheetResp = ss.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_RESP);
    const sheetExp = ss.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_EXP);
    
    // Difesa in profondità: intercettazione rapida di corruzione del database
    if(!sheetResp || !sheetExp) throw new Error("Fogli target irraggiungibili o rinominati.");

    const dataResp = sheetResp.getDataRange().getValues();
    const exportRows = [];
    const dataExport = new Date();

    // Loop iper-ottimizzato: caching della lunghezza dell'array e destrutturazione O(N)
    for (let i = 1, len = dataResp.length; i < len; i++) {
      // Estrazione mirata saltando le colonne non necessarie per limitare l'allocazione in memoria
      const [ , idIst, stato, , , rawJson ] = dataResp[i];
      
      // Filtro per stato coerente prima di tentare il costoso parsing JSON
      if (stato === 'INVIATO' && rawJson) {
        try {
          const parsed = JSON.parse(rawJson);
          const rows = Array.isArray(parsed) ? parsed : (parsed.rows || []);
          const flagNuova = (parsed.flag === true) ? "SI" : "NO";
          
          for(const r of rows) {
            exportRows.push([idIst, r.cf, r.azione, r.note || "", dataExport, flagNuova]);
          }
        } catch(e) {
          Logger.log(` Parsing JSON fallito alla riga ${i+1}. Ignorata.`);
        }
      }
    }
    
    if (exportRows.length > 0) {
      const lastRowExp = Math.max(sheetExp.getLastRow(), 1);
      if (lastRowExp > 1) {
        // Pulizia transazionale del range precedente
        sheetExp.getRange(2, 1, lastRowExp - 1, sheetExp.getLastColumn()).clearContent();
      }
      // Scrittura batch O(1) in una singola transazione API REST
      sheetExp.getRange(2, 1, exportRows.length, exportRows[0].length).setValues(exportRows);
      SpreadsheetApp.flush(); // Forza la persistenza fisica del dato
      Logger.log(`[JOB CESSAZIONI] Success: Esportate ${exportRows.length} righe.`);
    } else {
      Logger.log("[JOB CESSAZIONI] Nessun dato trovato da esportare.");
    }
  } catch(e) {
    Logger.log(" Fallimento durante syncExportTable_: " + e.message);
  } finally {
    // Rilascio garantito del mutex
    lock.releaseLock();
  }
}

/**
 * API RPC: Gestisce l'invio di una nuova richiesta di budget.
 * Il JSON_Blob viene strutturato qui lato server garantendo il logging completo.
 */
function submitBudgetRequest(token, payload) {
  try {
    // GUARDIA PREVENTIVA: Master Switch (Previene chiamate RPC forzate a modulo chiuso)
    if (!isScambioBudgetAttivo()) {
        throw new Error("Il modulo Scambio Budget è attualmente disabilitato dal Ministero. Operazione bloccata.");
    }

    var userCtx = verifySessionAndGetUser(token);
    var idRichiedente = String(userCtx.istituzioneId);
    var idCedente = String(payload.cedenteId).trim();

    // Security: Impedisce a un'istituzione di cedere fondi a se stessa
    if (idRichiedente === idCedente) {
        throw new Error("Non è possibile richiedere budget alla propria istituzione.");
    }

// Zero Trust: Validazione rigorosa dell'importo. 
    // Usiamo Number() invece di parseFloat() per rifiutare stringhe miste testuali ("100abc" -> NaN)
    // Impediamo valori negativi, zero, Type Confusion e iniezioni di Array/Object.
    var importo = Number(payload.importo);
    if (isNaN(importo) || importo <= 0 || typeof payload.importo === 'boolean' || typeof payload.importo === 'object') {
        throw new Error("Errore di sicurezza: Importo non valido, corrotto o manipolato.");
    }
    // Normalizzazione a 2 decimali come standard valutario e cast a Number puro
    importo = Math.round(importo * 100) / 100;

    if (payload.confermaDelibera !== true) {
        throw new Error("È obbligatorio confermare la delibera di variazione di organico.");
    }

    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGETORGANICO);
    var sheetBase = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
    var sheetTrans = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    
    if (!sheetBase || !sheetTrans) {
        throw new Error("Errore DB: Impossibile trovare i fogli. Verifica che i fogli " + DB_CONFIG.SHEET_BUDGET_BASE + " e " + DB_CONFIG.SHEET_BUDGET_TRANS + " esistano nel Google Sheet.");
    }

// --- FASE 1: LETTURE E CALCOLO IN MEMORIA (Fuori dal Lock) ---
    // Zero Trust & Performance: 1 singola chiamata API (I/O Bulk) 
    const baseData = sheetBase.getDataRange().getValues();
    
    // O(N) Lookup iper-veloce in RAM
    const rowCedente = baseData.find((row, idx) => idx > 0 && String(row[COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]).trim() === idCedente);
    const budgetInizialeCedente = rowCedente ? (parseFloat(rowCedente[COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0) : 0;

    // --- CALCOLO SALDO CEDENTE (IN RAM) ---
    let usciteCedente = 0;
    let entrateCedente = 0;
    const initialLastRow = sheetTrans.getLastRow();
    
    if (initialLastRow > 1) {
        // 1 singola chiamata API bulk per l'intero storico
        const transData = sheetTrans.getRange(2, 1, initialLastRow - 1, sheetTrans.getLastColumn()).getValues();
        
        // Loop in RAM ES6
        transData.forEach(row => {
            const tReqId = String(row[COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
            const tCedId = String(row[COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
            const tStato = row[COL_MAP.BUDGET_TRANS.STATO];
            
            // Skip rapido per risparmiare cicli CPU (Culling)
            if (tReqId !== idCedente && tCedId !== idCedente) return;
            
            let tImporto = 0;
            try { 
                tImporto = parseFloat(JSON.parse(row[COL_MAP.BUDGET_TRANS.JSON_BLOB]).importo_richiesto) || 0; 
            } catch(e) {}

            if (tReqId === idCedente && tStato === 'ACCETTATA') entrateCedente += tImporto;
            if (tCedId === idCedente && ['ACCETTATA', 'INVIATA', 'IN_INTEGRAZIONE'].includes(tStato)) usciteCedente += tImporto;
        });
    }

    // --- FASE 2: SEZIONE CRITICA (Sotto Lock) ---
    const lock = LockService.getScriptLock();
    if (!lock.tryLock(30000)) {
      throw new Error("Il sistema è momentaneamente occupato a causa di un elevato numero di richieste. Riprovare tra qualche secondo.");
    }

    try {
      SpreadsheetApp.flush();
      const currentLastRow = sheetTrans.getLastRow();
      
      // Calcolo ultra-veloce del DELTA (transazioni avvenute mentre eravamo in attesa del lock)
      if (currentLastRow > initialLastRow) {
          const deltaRows = currentLastRow - initialLastRow;
          const deltaData = sheetTrans.getRange(initialLastRow + 1, 1, deltaRows, sheetTrans.getLastColumn()).getValues();
          
          deltaData.forEach(row => {
              const dReqId = String(row[COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
              const dCedId = String(row[COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
              const dStato = row[COL_MAP.BUDGET_TRANS.STATO];
              
              if (dReqId !== idCedente && dCedId !== idCedente) return;
              
              let dImporto = 0;
              try { 
                  dImporto = parseFloat(JSON.parse(row[COL_MAP.BUDGET_TRANS.JSON_BLOB]).importo_richiesto) || 0; 
              } catch(e) {}

              if (dReqId === idCedente && dStato === 'ACCETTATA') entrateCedente += dImporto;
              if (dCedId === idCedente && ['ACCETTATA', 'INVIATA', 'IN_INTEGRAZIONE'].includes(dStato)) usciteCedente += dImporto;
          });
      }

      const saldoDisponibileCedente = budgetInizialeCedente + entrateCedente - usciteCedente;
      if (importo > saldoDisponibileCedente) {
          throw new Error("Fondi insufficienti/già prenotati da altri enti.");
      }

      // --- SALVATAGGIO TRANSAZIONE ---
      var now = new Date().toISOString();
      var dataBlob = {
        importo_richiesto: importo,
        conferma_delibera: payload.confermaDelibera,
        history: [
          {
            timestamp: now,
            attore: userCtx.username, // FIX LOG: Tracciamo l'utente reale dall'oggetto sessione
            ruolo_attore: "RICHIEDENTE",
            azione: "CREAZIONE_E_INVIO",
            note: payload.note ? String(payload.note).trim() : ""
          }
        ]
      };
      
      var idTransazione = Utilities.getUuid();
      var statoIniziale = "INVIATA"; 

      sheetTrans.appendRow([
        idTransazione,
        idRichiedente,
        idCedente,
        statoIniziale,
        JSON.stringify(dataBlob)
      ]);
      SpreadsheetApp.flush(); 
      return { success: true };
    } finally {
      lock.releaseLock();
    }

  } catch (e) {
    Logger.log("Errore submitBudgetRequest: " + e.message);
    throw new Error(e.message);
  }
}

/**
 * API RPC: Recupera i dati della dashboard Scambio Budget
 * Zero Trust: Calcola i saldi e le transazioni dinamicamente lato server
 */
function getBudgetDashboardData(token) {
  try {
    var userCtx = verifySessionAndGetUser(token);
    var ruolo = String(userCtx.ruolo).toUpperCase().trim();
    var isAdmin = (ruolo === 'ADMIN' || ruolo === 'MINISTERO');
    var myIstId = String(userCtx.istituzioneId);
    
    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGETORGANICO);
var sheetTrans = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    
    // Ottimizzazione: Lettura Anagrafica Base con Caching Distribuito
    var cache = CacheService.getScriptCache();
    var cachedBase = cache.get("CACHE_BUDGET_BASE");
    var mapIstituzioni = {}; 
    var listIstituzioni = [];
    
    if (cachedBase) {
        var parsedBase = JSON.parse(cachedBase);
        mapIstituzioni = parsedBase.map;
        listIstituzioni = parsedBase.list;
    } else {
        var sheetBase = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
        var baseData = sheetBase ? sheetBase.getDataRange().getValues() : [];
        for(var i=1; i<baseData.length; i++) {
            var id = String(baseData[i][COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]).trim();
            var nome = baseData[i][COL_MAP.BUDGET_BASE.DENOMINAZIONE];
            var budgetBase = parseFloat(baseData[i][COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0;
            mapIstituzioni[id] = { nome: nome, budgetBase: budgetBase };
            listIstituzioni.push({id: id, nome: nome}); // Memorizzazione globale
        }
        cache.put("CACHE_BUDGET_BASE", JSON.stringify({map: mapIstituzioni, list: listIstituzioni}), 21600); // 6 ore di cache
    }
    
    // Estrazione finale filtrando sé stessi
    listIstituzioni = listIstituzioni.filter(ist => ist.id !== myIstId);

    // 2. Lettura Transazioni
    var transData = sheetTrans ? sheetTrans.getDataRange().getValues() : [];
    
    if (isAdmin) {
        // --- LOGICA REPORTISTICA MINISTERO ---
        var report = {};
        for (var idIst in mapIstituzioni) {
            report[idIst] = { 
                id: idIst, 
                nome: mapIstituzioni[idIst].nome, 
                budgetBase: mapIstituzioni[idIst].budgetBase, 
                valoreScambio: 0, 
                residuo: mapIstituzioni[idIst].budgetBase, 
                transazioni: [] 
            };
        }
        
        for (var t=1; t<transData.length; t++) {
            var reqId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
            var cedId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
            var stato = transData[t][COL_MAP.BUDGET_TRANS.STATO];
            var rawJson = transData[t][COL_MAP.BUDGET_TRANS.JSON_BLOB];
            
            var payload = {};
            try { payload = JSON.parse(rawJson); } catch(e){}
            var importo = parseFloat(payload.importo_richiesto) || 0;
            var histDate = (payload.history && payload.history.length > 0) ? payload.history[0].timestamp : "";
            var dataFormattata = histDate ? Utilities.formatDate(new Date(histDate), "Europe/Rome", "dd/MM/yyyy") : "";
            
            var baseTrans = { id: transData[t][0], data: dataFormattata, importo: importo, stato: stato };
            
            if (stato === 'ACCETTATA') {
                if (report[reqId]) {
                    report[reqId].valoreScambio += importo;
                    report[reqId].residuo += importo;
                    report[reqId].transazioni.push(Object.assign({}, baseTrans, {tipo: "ACQUISITO (Da " + (mapIstituzioni[cedId]?mapIstituzioni[cedId].nome:cedId) + ")"}));
                }
                if (report[cedId]) {
                    report[cedId].valoreScambio -= importo;
                    report[cedId].residuo -= importo;
                    report[cedId].transazioni.push(Object.assign({}, baseTrans, {tipo: "CEDUTO (A " + (mapIstituzioni[reqId]?mapIstituzioni[reqId].nome:reqId) + ")"}));
                }
            } else {
                 if (report[reqId]) report[reqId].transazioni.push(Object.assign({}, baseTrans, {tipo: "RICHIESTA INVIATA (A " + (mapIstituzioni[cedId]?mapIstituzioni[cedId].nome:cedId) + ")"}));
                 if (report[cedId]) report[cedId].transazioni.push(Object.assign({}, baseTrans, {tipo: "RICHIESTA RICEVUTA (Da " + (mapIstituzioni[reqId]?mapIstituzioni[reqId].nome:reqId) + ")"}));
            }
        }
        
        var finalReport = Object.keys(report).map(function(k){ return report[k]; });
        finalReport.sort(function(a,b) { return a.nome.localeCompare(b.nome); });

        var props = PropertiesService.getScriptProperties();
        var isAttivo = props.getProperty('SCAMBIO_BUDGET_ATTIVO') === 'TRUE';
        
        return { success: true, isAdmin: true, report: finalReport, isAttivo: isAttivo };
        
    } else {
        // --- LOGICA DASHBOARD ISTITUZIONE ---
        var myBudgetBase = mapIstituzioni[myIstId] ? mapIstituzioni[myIstId].budgetBase : 0;
        var entrate = 0; var uscitePendenza = 0; var usciteAccettate = 0;
        var myTrans = [];

        var countRichiesteAttive = 0;
        var countScambiAccettati = 0;
        var countScambiRifiutati = 0;

        for (var t=1; t<transData.length; t++) {
            var reqId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
            var cedId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
            
            if (reqId === myIstId || cedId === myIstId) {
                var stato = transData[t][COL_MAP.BUDGET_TRANS.STATO];
                var rawJson = transData[t][COL_MAP.BUDGET_TRANS.JSON_BLOB];
                
                var payload = {};
                // Questo try-catch interno è corretto e non dà problemi
                try { payload = JSON.parse(rawJson); } catch(e){} 
                var importo = parseFloat(payload.importo_richiesto) || 0;
                var histDate = (payload.history && payload.history.length > 0) ? payload.history[0].timestamp : "";
                var dataFormattata = histDate ? Utilities.formatDate(new Date(histDate), "Europe/Rome", "dd/MM/yyyy") : "";
                
                var isRichiedente = (reqId === myIstId);
                var partnerId = isRichiedente ? cedId : reqId;
                var partnerNome = mapIstituzioni[partnerId] ? mapIstituzioni[partnerId].nome : partnerId;
                
                if (isRichiedente && stato === 'ACCETTATA') entrate += importo;
                if (!isRichiedente && stato === 'ACCETTATA') usciteAccettate += importo;
                if (!isRichiedente && (stato === 'INVIATA' || stato === 'IN_INTEGRAZIONE')) uscitePendenza += importo;

                // Calcolo statistiche visive per i riquadri
                if (stato === 'INVIATA' || stato === 'IN_INTEGRAZIONE' || stato === 'BOZZA_CEDENTE') {
                    countRichiesteAttive++;
                } else if (stato === 'ACCETTATA') {
                    countScambiAccettati++;
                } else if (stato === 'RIFIUTATA') {
                    countScambiRifiutati++;
                }

                myTrans.push({
                    id: transData[t][COL_MAP.BUDGET_TRANS.ID_TRANS], data: dataFormattata,
                    tipo: isRichiedente ? 'INVIATA' : 'RICEVUTA',
                    partner: partnerNome, importo: importo, stato: stato
                });
            }
        }
        
return {
            success: true, 
            isAdmin: false,
            stats: { 
                saldoIniziale: myBudgetBase, 
                entrateAccettate: entrate, 
                uscitePendenza: uscitePendenza,
                usciteAccettate: usciteAccettate,
                uscitePendenti: (usciteAccettate + uscitePendenza), 
                saldoDisponibile: (myBudgetBase + entrate - usciteAccettate - uscitePendenza),
                richiesteAttive: countRichiesteAttive,
                scambiAccettati: countScambiAccettati,
                scambiRifiutati: countScambiRifiutati
            },
            transazioni: myTrans, 
            istituzioni: listIstituzioni
        };
        
// INIZIO MODIFICA
    } // <-- Aggiunta chiusura del blocco 'else'
// FINE MODIFICA

// La parentesi chiusa prima di catch chiude esattamente il try aperto in alto
  } catch (e) { 
    return { success: false, message: "Errore Dashboard: " + e.message };
  }
}

/**
 * API RPC (Admin): Cambia lo stato del Master Switch.
 */
function toggleScambioBudget(token, newState) {
    try {
        var userCtx = verifySessionAndGetUser(token);
        if (String(userCtx.ruolo).toUpperCase() !== 'ADMIN' && String(userCtx.ruolo).toUpperCase() !== 'MINISTERO') {
            throw new Error("Non autorizzato.");
        }
        
        var props = PropertiesService.getScriptProperties();
        // Converte in stringa 'TRUE' o 'FALSE'
        props.setProperty('SCAMBIO_BUDGET_ATTIVO', newState ? 'TRUE' : 'FALSE');
        
        return { success: true, message: newState ? "Modulo ATTIVATO." : "Modulo DISATTIVATO." };
    } catch(e) {
        return { success: false, message: e.message };
    }
}

/**
 * Esegue l'annullamento con protezione per Ministero e Admin (Rollback Condizionato)
 * Sostituisce tutte le versioni precedenti di annullaTransazioneMinistero e rimuove la dipendenza da validazioneToken
 */
function annullaTransazioneMinistero(token, idTrans) {
    // 1. VALIDAZIONE E RECUPERO DATI FUORI DAL LOCK (Lock Striping)
    const userCtx = verifySessionAndGetUser(token);
    const ruolo = String(userCtx.ruolo).toUpperCase().trim();
    
    if (ruolo !== 'ADMIN' && ruolo !== 'MINISTERO') {
        Logger.log(`[SECURITY] Tentativo di annullamento illegale da: ${userCtx.username}`);
        throw new Error("Autorizzazione insufficiente: Funzione riservata al Ministero o Admin.");
    }

    const ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGETORGANICO);
    const sheetTransazioni = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    
    // Lettura iniziale fuori lock
    const finder = sheetTransazioni.getRange(1, COL_MAP.BUDGET_TRANS.ID_TRANS + 1, sheetTransazioni.getLastRow(), 1)
                                   .createTextFinder(idTrans).matchEntireCell(true);
    const cellTrans = finder.findNext();
    if (!cellTrans) throw new Error("Transazione non trovata.");
    
    const rigaTransazione = cellTrans.getRow();
    const transazione = sheetTransazioni.getRange(rigaTransazione, 1, 1, sheetTransazioni.getLastColumn()).getValues()[0];
    const stato = transazione[COL_MAP.BUDGET_TRANS.STATO];
    
    if (stato !== 'ACCETTATA') throw new Error("Solo le transazioni in stato ACCETTATA possono essere annullate.");
    
    let payload = {};
    try { payload = JSON.parse(transazione[COL_MAP.BUDGET_TRANS.JSON_BLOB]); } 
    catch(e) { throw new Error("Dati transazione corrotti."); }
    
    const idAcquirente = String(transazione[COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
    
    // 2. PRE-CALCOLO SALDI IN MEMORIA
    const sheetBase = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
    const baseData = sheetBase.getDataRange().getValues();
    let budgetInizialeAcq = 0;
    
    for(let i=1; i<baseData.length; i++) {
        if(String(baseData[i][COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]).trim() === idAcquirente) {
            budgetInizialeAcq = parseFloat(baseData[i][COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0;
            break;
        }
    }
    
    const initialLastRow = sheetTransazioni.getLastRow();
    let entrateAcq = 0;
    let usciteAcq = 0;
    
    if (initialLastRow > 1) {
        const transData = sheetTransazioni.getRange(2, 1, initialLastRow - 1, sheetTransazioni.getLastColumn()).getValues();
        transData.forEach(row => {
            if(row[COL_MAP.BUDGET_TRANS.ID_TRANS] === idTrans) return; // Escludo transazione da stornare
            const reqId = String(row[COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
            const cedId = String(row[COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
            const tStato = row[COL_MAP.BUDGET_TRANS.STATO];
            
            if (reqId !== idAcquirente && cedId !== idAcquirente) return; // Culling immediato
            
            let tImporto = 0;
            try { tImporto = parseFloat(JSON.parse(row[COL_MAP.BUDGET_TRANS.JSON_BLOB]).importo_richiesto) || 0; } catch(e){}
            
            if (reqId === idAcquirente && tStato === 'ACCETTATA') entrateAcq += tImporto;
            if (cedId === idAcquirente && ['ACCETTATA', 'INVIATA', 'IN_INTEGRAZIONE'].includes(tStato)) usciteAcq += tImporto;
        });
    }

    // 3. SEZIONE CRITICA (Latenza ridotta drasticamente)
    const lock = LockService.getScriptLock();
    try {
        if (!lock.tryLock(15000)) throw new Error("Sistema occupato, riprova.");
        Logger.log(`[ROLLBACK] Avvio procedura per ID: ${idTrans} richiesto da ${ruolo}`);
        SpreadsheetApp.flush();
        
        // Calcolo Delta (eventuali scritture avvenute in altri theard durante il tryLock)
        const currentLastRow = sheetTransazioni.getLastRow();
        if (currentLastRow > initialLastRow) {
            const deltaRows = currentLastRow - initialLastRow;
            const deltaData = sheetTransazioni.getRange(initialLastRow + 1, 1, deltaRows, sheetTransazioni.getLastColumn()).getValues();
            
            deltaData.forEach(row => {
                if(row[COL_MAP.BUDGET_TRANS.ID_TRANS] === idTrans) return;
                const reqId = String(row[COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
                const cedId = String(row[COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
                const dStato = row[COL_MAP.BUDGET_TRANS.STATO];
                
                if (reqId !== idAcquirente && cedId !== idAcquirente) return;
                
                let dImporto = 0;
                try { dImporto = parseFloat(JSON.parse(row[COL_MAP.BUDGET_TRANS.JSON_BLOB]).importo_richiesto) || 0; } catch(e){}
                
                if (reqId === idAcquirente && dStato === 'ACCETTATA') entrateAcq += dImporto;
                if (cedId === idAcquirente && ['ACCETTATA', 'INVIATA', 'IN_INTEGRAZIONE'].includes(dStato)) usciteAcq += dImporto;
            });
        }
        
        const saldoDisponibilePostRollback = budgetInizialeAcq + entrateAcq - usciteAcq;
        if (saldoDisponibilePostRollback < 0) {
            Logger.log(`[ROLLBACK NEGATO] ID: ${idTrans}. Saldo insufficiente (${saldoDisponibilePostRollback}).`);
            throw new Error(`Impossibile annullare: l'istituzione ha già impegnato i fondi acquisiti in scambi successivi. Il rollback porterebbe il saldo in negativo.`);
        }
        
        // Find posizionale sotto-lock prima della scrittura
        const finderSafe = sheetTransazioni.getRange(1, COL_MAP.BUDGET_TRANS.ID_TRANS + 1, currentLastRow, 1).createTextFinder(idTrans).matchEntireCell(true);
        const cellSafe = finderSafe.findNext();
        if(!cellSafe) throw new Error("Transazione non trovata durante la scrittura.");
        const rigaDefinitiva = cellSafe.getRow();
        
        payload.history = payload.history || [];
        payload.history.push({
            timestamp: new Date().toISOString(),
            attore: userCtx.username,
            ruolo_attore: ruolo,
            azione: "ANNULLAMENTO_MINISTERO",
            note: `Annullata da ${ruolo} in data ${new Date().toLocaleDateString('it-IT')}`
        });
        
        sheetTransazioni.getRange(rigaDefinitiva, COL_MAP.BUDGET_TRANS.STATO + 1).setValue('ANNULLATA_MINISTERO');
        sheetTransazioni.getRange(rigaDefinitiva, COL_MAP.BUDGET_TRANS.JSON_BLOB + 1).setValue(JSON.stringify(payload));
        
        SpreadsheetApp.flush();
        Logger.log(`[ROLLBACK COMPLETATO] Transazione ${idTrans} annullata con successo.`);
        
        return { success: true, message: "Transazione annullata. I fondi sono stati stornati." };
    } catch (e) {
        Logger.log("Errore annullaTransazioneMinistero: " + e.message);
        return { success: false, message: e.message };
    } finally {
        lock.releaseLock();
    }
}

/**
 * API RPC: Recupera lo storico transazioni di una singola istituzione per la Dashboard Ministeriale.
 * @param {string} token Session token dell'admin.
 * @param {string} idIstituzione ID dell'istituzione di cui visualizzare il dettaglio.
 */
function getStoricoIstituzione(token, idIstituzione) {
  try {
    var userCtx = verifySessionAndGetUser(token);
    var ruolo = String(userCtx.ruolo).toUpperCase().trim();
    
    if (ruolo !== 'ADMIN' && ruolo !== 'MINISTERO') {
        throw new Error("Accesso negato: Permessi insufficienti.");
    }

    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGETORGANICO);
    var sheetBase = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
    var sheetTrans = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);

    // Mappa Anagrafica per recuperare i nomi della controparte
    var baseData = sheetBase ? sheetBase.getDataRange().getValues() : [];
    var mapIstituzioni = {};
    for (var i = 1; i < baseData.length; i++) {
        var id = String(baseData[i][COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]).trim();
        mapIstituzioni[id] = baseData[i][COL_MAP.BUDGET_BASE.DENOMINAZIONE];
    }

    var transData = sheetTrans ? sheetTrans.getDataRange().getValues() : [];
    var storico = [];

    for (var t = 1; t < transData.length; t++) {
        var reqId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
        var cedId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();

        if (reqId === idIstituzione || cedId === idIstituzione) {
            var stato = transData[t][COL_MAP.BUDGET_TRANS.STATO];
            var rawJson = transData[t][COL_MAP.BUDGET_TRANS.JSON_BLOB];
            
            var payload = {};
            try { payload = JSON.parse(rawJson); } catch(e){}
            
            var importo = parseFloat(payload.importo_richiesto) || 0;
            var histDate = (payload.history && payload.history.length > 0) ? payload.history[0].timestamp : "";
            var dataFormattata = histDate ? Utilities.formatDate(new Date(histDate), "Europe/Rome", "dd/MM/yyyy") : "";
            
            var isRichiedente = (reqId === idIstituzione);
            var partnerId = isRichiedente ? cedId : reqId;
            var partnerNome = mapIstituzioni[partnerId] ? mapIstituzioni[partnerId] : partnerId;
            
            var tipoTransazione = "";
            if (stato === 'ACCETTATA') {
                tipoTransazione = isRichiedente ? "ACQUISITO" : "CEDUTO";
            } else {
                tipoTransazione = isRichiedente ? "RICHIESTA INVIATA" : "RICHIESTA RICEVUTA";
            }

        storico.push({
                idTrans: transData[t][COL_MAP.BUDGET_TRANS.ID_TRANS],
                data: dataFormattata,
                tipo: tipoTransazione,
                importo: importo,
                controparte: partnerNome,
                stato: stato
            });
        }
    }

    // Ordine cronologico inverso (Le più recenti in alto)
    storico.reverse();

    return { success: true, storico: storico };

  } catch (e) {
    Logger.log("Errore getStoricoIstituzione: " + e.message);
    return { success: false, message: e.message };
  }
}

/**
 * Aggiorna lo stato di una richiesta nel foglio BUDGET_TRANS
 * Implementa logica Zero Trust verificando l'identità dell'istituzione
 */
function updateBudgetRequestStatus(token, id, azione) {
  const lock = LockService.getScriptLock();
  try {
    // 1. Validazione Sessione (Zero Trust)
    const userCtx = verifySessionAndGetUser(token);
    const idIstituzione = String(userCtx.istituzioneId).trim();
    
    // 2. Lock preventivo (Pessimistic Locking)
    if (!lock.tryLock(10000)) {
      throw new Error("Il sistema è occupato da un'altra operazione. Riprovare tra pochi secondi.");
    }

    const ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGETORGANICO);
    const sheet = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
const searchRange = sheet.getRange(1, COL_MAP.BUDGET_TRANS.ID_TRANS + 1, sheet.getLastRow(), 1);
    const finder = searchRange.createTextFinder(id).matchEntireCell(true);
    const result = finder.findNext();

    if (!result) throw new Error("Transazione non trovata nel database.");

    const rowIndex = result.getRow();
    // Legge SOLO la riga necessaria (drastica riduzione latenza e RAM)
    const transazione = sheet.getRange(rowIndex, 1, 1, sheet.getLastColumn()).getValues()[0];

    // 4. Verifiche di Dominio (Integrità)
    const idCedente = String(transazione[COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
    const statoAttuale = transazione[COL_MAP.BUDGET_TRANS.STATO];

    if (idCedente !== idIstituzione) {
      throw new Error("Accesso negato: Solo l'istituzione cedente autorizzata può approvare o rifiutare i fondi.");
    }
    
    if (statoAttuale !== 'INVIATA' && statoAttuale !== 'IN_INTEGRAZIONE') {
      throw new Error(`Operazione bloccata: La pratica si trova in uno stato irreversibile (${statoAttuale}).`);
    }

    if (azione !== 'ACCETTATA' && azione !== 'RIFIUTATA') {
      throw new Error("Codice azione non valido.");
    }

    // 5. Aggiornamento Payload (Audit Log su JSON_BLOB)
    let payload = {};
    try {
      payload = JSON.parse(transazione[COL_MAP.BUDGET_TRANS.JSON_BLOB]);
    } catch(e) { payload = { history: [] }; }

// Controllo capienza portafoglio reiterato in fase di ACCETTAZIONE sotto lock (Prevenzione Race Condition / Variazione Budget Base)
    if (azione === 'ACCETTATA') {
      const sheetBase = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
      const baseData = sheetBase.getDataRange().getValues();
      const rowCedente = baseData.find((row, idx) => idx > 0 && String(row[COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]).trim() === idCedente);
      const budgetInizialeCedente = rowCedente ? (parseFloat(rowCedente[COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0) : 0;
      
      let usciteCedente = 0;
      let entrateCedente = 0;
      const transData = sheet.getDataRange().getValues();
      
      transData.forEach((row, idx) => {
        if (idx === 0) return; // Salta header
        const tReqId = String(row[COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
        const tCedId = String(row[COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
        const tStato = row[COL_MAP.BUDGET_TRANS.STATO];
        
        if (tReqId !== idCedente && tCedId !== idCedente) return;
        
        let tImporto = 0;
        try { 
          tImporto = parseFloat(JSON.parse(row[COL_MAP.BUDGET_TRANS.JSON_BLOB]).importo_richiesto) || 0; 
        } catch(e) {}

        if (tReqId === idCedente && tStato === 'ACCETTATA') entrateCedente += tImporto;
        if (tCedId === idCedente && ['ACCETTATA', 'INVIATA', 'IN_INTEGRAZIONE'].includes(tStato)) {
          // Escludiamo la transazione corrente per calcolare il saldo disponibile PRIMA di questa uscita
          if (row[COL_MAP.BUDGET_TRANS.ID_TRANS] !== id) usciteCedente += tImporto;
        }
      });
      
      const currentImporto = parseFloat(payload.importo_richiesto) || 0;
      const saldoDisponibile = budgetInizialeCedente + entrateCedente - usciteCedente;
      
      if (currentImporto > saldoDisponibile) {
        throw new Error("Saldo insufficiente al momento dell'accettazione. Il budget base è stato modificato o i fondi sono impegnati altrove.");
      }
    }

    payload.history = payload.history || [];
    payload.history.push({
      timestamp: new Date().toISOString(),
      attore: userCtx.username,
      ruolo_attore: "CEDENTE",
      azione: azione,
      note: `La richiesta è stata ${azione.toLowerCase()} dall'istituzione cedente.`
    });

    // 6. Scrittura transazionale su Google Sheets
    sheet.getRange(rowIndex, COL_MAP.BUDGET_TRANS.STATO + 1).setValue(azione);
    sheet.getRange(rowIndex, COL_MAP.BUDGET_TRANS.JSON_BLOB + 1).setValue(JSON.stringify(payload));
    
    Logger.log(`[AUDIT] Budget ${azione} | Transazione: ${id} | Operatore: ${userCtx.username}`);
    SpreadsheetApp.flush();
    
    return { success: true };
    
  } catch(e) {
    Logger.log("[ERROR] updateBudgetRequestStatus: " + e.message);
return { success: false, message: e.message };
  } finally {
    lock.releaseLock();
  }
}

/**
 * TRIGGER NOTTURNO reso strettamente privato.
 * Sincronizzazione Export Budget (BUDGET_TRANS -> BUDGET_EXP).
 * L'aggiunta dell'underscore finale impedisce fisicamente a google.script.run 
 * di risolvere e mappare l'endpoint, bloccando l'esecuzione anonima.
 */
function syncBudgetExportTable_() {
  const lock = LockService.getScriptLock();
  try {
    // Timeout ridotto drasticamente a 5 secondi per i job in background.
    // Previene stalli irreversibili della coda di esecuzione in caso di conflitti.
    if (!lock.tryLock(5000)) {
      Logger.log(" Tentativo di sync interrotto: Lock di sistema occupato.");
      return;
    }
  } catch(e) {
    return;
  }

  try {
    const fileBudget = DriveApp.getFileById(DB_CONFIG.ID_BUDGETORGANICO);
    const lastModifiedTime = fileBudget.getLastUpdated().getTime();
    
    const scriptProperties = PropertiesService.getScriptProperties();
    const lastSyncTime = parseInt(scriptProperties.getProperty('BUDGET_LAST_SYNC_TIME')) || 0;

    if (lastModifiedTime <= lastSyncTime) {
      Logger.log("[JOB BUDGET] Nessuna modifica rilevata al DB Budget dall'ultima esecuzione. Early Exit.");
      return;
    }

    const ssBudget = SpreadsheetApp.open(fileBudget);
    const sheetBase = ssBudget.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
    const sheetTrans = ssBudget.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    const sheetExp = ssBudget.getSheetByName(DB_CONFIG.SHEET_BUDGET_EXP);

    // Difesa in profondità: intercettazione rapida di corruzione del database
    if(!sheetBase || !sheetTrans || !sheetExp) throw new Error("Fogli target irraggiungibili o rinominati.");

    // 1. Caricamento Anagrafica e Saldi
    const baseData = sheetBase.getDataRange().getValues();
    const mapBalances = {};
    const mapNames = {};
    for (let b = 1, len = baseData.length; b < len; b++) {
      const id = String(baseData[b][COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]);
      mapBalances[id] = parseFloat(baseData[b][COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0;
      mapNames[id] = baseData[b][COL_MAP.BUDGET_BASE.DENOMINAZIONE];
    }

    // 2. Recupero ID_TRANS già esportati (Set Lookup O(1))
    const lastRowExp = Math.max(sheetExp.getLastRow(), 1);
    const exportedIds = new Set();
    if (lastRowExp > 1) {
      const existingIds = sheetExp.getRange(2, COL_MAP.BUDGET_EXP.ID_TRANS + 1, lastRowExp - 1, 1).getValues();
      existingIds.forEach(row => exportedIds.add(String(row[0])));
    }

    // 3. Elaborazione sequenziale transazioni
    const transData = sheetTrans.getDataRange().getValues();
    const rowsToExport = [];

    // Loop iper-ottimizzato: caching della lunghezza dell'array e destrutturazione posizionale
    for (let t = 1, len = transData.length; t < len; t++) {
      // Estrazione mirata che salta l'allocazione selettiva non necessaria
      const [ idTransRaw, reqIdRaw, cedIdRaw, stato, rawJsonBlob ] = transData[t];
      
      // Filtro per stato coerente ED esistenza set prima del parsing JSON costoso
      if (stato === 'ACCETTATA' && !exportedIds.has(String(idTransRaw))) {
        try {
          const idTrans = String(idTransRaw);
          const reqId = String(reqIdRaw);
          const cedId = String(cedIdRaw);

          const payload = JSON.parse(rawJsonBlob || "{}");
          const importo = parseFloat(payload.importo_richiesto) || 0;

          // Cattura residui Ante
          const anteCed = mapBalances[cedId] || 0;
          const anteReq = mapBalances[reqId] || 0;

          // Aggiornamento Saldi Registro Temporaneo
          mapBalances[cedId] -= importo;
          mapBalances[reqId] += importo;

          rowsToExport.push([
            cedId, mapNames[cedId] || cedId, anteCed, mapBalances[cedId],
            reqId, mapNames[reqId] || reqId, anteReq, mapBalances[reqId],
            importo, idTrans 
          ]);
        } catch(e) {
          Logger.log(`[ERRORE] Parsing JSON fallito alla riga transazione ${t+1}. Ignorata.`);
        }
      }
    }

    // 4. Scrittura Batch O(1) in una singola transazione API REST
    if (rowsToExport.length > 0) {
      sheetExp.getRange(lastRowExp + 1, 1, rowsToExport.length, rowsToExport[0].length).setValues(rowsToExport);
      SpreadsheetApp.flush(); // Forza la persistenza fisica del dato
      Logger.log(`[JOB BUDGET] Success: Esportate ${rowsToExport.length} nuove occorrenze.`);
    } else {
      Logger.log("[JOB BUDGET] Nessuna nuova occorrenza trovata da esportare.");
    }

    // Aggiorna il timestamp di successo
    scriptProperties.setProperty('BUDGET_LAST_SYNC_TIME', new Date().getTime().toString());

  } catch (e) {
    Logger.log(" Fallimento durante syncBudgetExportTable_: " + e.message);
  } finally {
    // Rilascio garantito del mutex
    lock.releaseLock();
  }
}

/**
 * Registra l'accettazione di Privacy e Cookie per gli utenti esistenti che non l'avevano firmata.
 */
function updatePrivacyCookieAcceptance(token) {
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var userCtx = verifySessionAndGetUser(token);
    
    var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
    
    var timestampConsenso = Utilities.formatDate(new Date(), "Europe/Rome", "dd/MM/yyyy HH:mm:ss");
    var privacyLog = "ACCETTATO - " + timestampConsenso;
    var cookieLog = "ACCETTATO - " + timestampConsenso;
    
    // Aggiornamento sul foglio (Colonne Q e R - indici 17 e 18)
    sheetCred.getRange(userCtx.rowIndex, COL_MAP.CRED.ACCETTAZIONE_PRIVACY + 1).setValue(privacyLog);
    sheetCred.getRange(userCtx.rowIndex, COL_MAP.CRED.ACCETTAZIONE_COOKIE + 1).setValue(cookieLog);
    
    // Aggiornamento Cache
    userCtx.privacyLog = privacyLog;
    userCtx.cookieLog = cookieLog;
    CacheService.getScriptCache().put("SESSION_" + token, JSON.stringify(userCtx), 1200);
    
    SpreadsheetApp.flush();
    return { success: true };
  } catch (e) {
    Logger.log("Errore salvataggio privacy: " + e.message);
    return { success: false, message: e.message };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Annulla una transazione lato Istituzione (sia richiedente che cedente)
 */
function annullaTransazioneIstituzione(token, idTrans) {
  const sharedLock = LockService.getScriptLock();
try {
    // 1. Validazione Reale del Token SPOSTATA FUORI DAL LOCK
    const userCtx = verifySessionAndGetUser(token);
    const myIstId = String(userCtx.istituzioneId).trim();

    if (!sharedLock.tryLock(15000)) throw new Error("Sistema occupato, riprova.");
    
    const ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGETORGANICO);
    const sheet = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    
    // Ottimizzazione O(1) con TextFinder
    const finder = sheet.getRange(1, COL_MAP.BUDGET_TRANS.ID_TRANS + 1, sheet.getLastRow(), 1)
                        .createTextFinder(idTrans).matchEntireCell(true);
    const cell = finder.findNext();
    if (!cell) throw new Error("Transazione non trovata.");
    
    const rowIdx = cell.getRow();
    const rowData = sheet.getRange(rowIdx, 1, 1, sheet.getLastColumn()).getValues()[0];
    const stato = rowData[COL_MAP.BUDGET_TRANS.STATO];
    
    const idRichiedente = String(rowData[COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
    const idCedente = String(rowData[COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();

    // 2. Verifica Autorizzazione: Solo le parti coinvolte possono annullare
    if (myIstId !== idRichiedente && myIstId !== idCedente) {
      throw new Error("Non sei autorizzato ad annullare questa transazione.");
    }

    // 3. Verifica Stato
    if (stato === 'RIFIUTATA') throw new Error("Non è possibile annullare una richiesta già rifiutata.");
    if (stato.includes('ANNULLATA')) throw new Error("La transazione è già annullata.");
    if (stato === 'ACCETTATA') {
      throw new Error("Le transazioni già ACCETTATE possono essere annullate solo dal Ministero. Contatta l'assistenza.");
    }

    // 4. Estrazione e Aggiornamento JSON_BLOB (Audit Log)
    let payload = {};
    try { payload = JSON.parse(rowData[COL_MAP.BUDGET_TRANS.JSON_BLOB]); } catch(e) { payload = {history:[]}; }
    
    payload.history = payload.history || [];
    payload.history.push({
        timestamp: new Date().toISOString(),
        attore: userCtx.username,
        ruolo_attore: "ISTITUZIONE",
        azione: "ANNULLAMENTO_ISTITUZIONE",
        note: "Operazione annullata dall'istituzione (" + myIstId + ")"
    });

    // 5. Scrittura transazionale
    sheet.getRange(rowIdx, COL_MAP.BUDGET_TRANS.STATO + 1).setValue('ANNULLATA_ISTITUTO');
    sheet.getRange(rowIdx, COL_MAP.BUDGET_TRANS.JSON_BLOB + 1).setValue(JSON.stringify(payload));
    
    SpreadsheetApp.flush();
    Logger.log(`[AUDIT] Transazione ${idTrans} annullata da ${myIstId}`);
    
    return { success: true, message: "Transazione annullata con successo." };
    
  } catch (e) {
    Logger.log("Errore annullaTransazioneIstituzione: " + e.message);
    // Ritorno un oggetto d'errore pulito per il Frontend
    return { success: false, message: e.message };
  } finally {
    sharedLock.releaseLock();
  }
}