/**
 * PORTALE GESTIONALE AFAM - BACKEND
 * Versione: 14.6 (Fix Checkbox Persistence & Export)
 */

// --- CONFIGURAZIONE SICURA ---
var scriptProperties = PropertiesService.getScriptProperties();

var DB_CONFIG = {
"MASTER_ID": scriptProperties.getProperty('MASTER_ID'),
  "SHEET_ISTITUZIONI": "ISTITUZIONI",
  "SHEET_ANAGRAFICA": "ANAGRAFICA_UTENTI",
  "SHEET_CREDENZIALI": "CREDENZIALI_ACCESSO",
  "ID_CESSAZIONI": scriptProperties.getProperty('ID_CESSAZIONI'),
  "SHEET_CESSAZIONI_ANAG": "ANAGRAFICA_CESSAZIONI",
  "SHEET_CESSAZIONI_RESP": "RISPOSTE_ISTITUZIONI",
  "SHEET_CESSAZIONI_EXP": "EXPORT_DATI_CESSAZIONI",
  "ID_BUDGET": scriptProperties.getProperty('ID_BUDGET'),
  "SHEET_BUDGET_BASE": "BUDGET_BASE",
  "SHEET_BUDGET_TRANS": "BUDGET_TRANSAZIONI",
  "SHEET_BUDGET_EXP": "EXPORT_BUDGET"
};

// Mappa delle colonne centralizzata
var COL_MAP = {
  CRED: {
    ID: 0, CF: 1, ISTITUZIONE_ID: 2, NOME: 3, COGNOME: 4, USERNAME: 5,
    HASH: 6, SALT: 7, RUOLO: 8, PIN: 9, STATO: 11, SESSION_ID: 14, LAST_LOGIN: 15
  },
  ANAG_CESS: {
    ID_CESSAZIONE: 0, ID_ISTITUZIONE: 1, NOME: 3, COGNOME: 4, CF: 5, QUALIFICA: 6
  },
  // Mapping Colonne Modulo Budget
  BUDGET_BASE: {
    ID_ISTITUZIONE: 0, DENOMINAZIONE: 1, BUDGET_INIZIALE: 2
  },
  BUDGET_TRANS: {
    ID_TRANS: 0, ID_RICHIEDENTE: 1, ID_CEDENTE: 2, STATO: 3, JSON_BLOB: 4
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

// --- CORE: GESTIONE SESSIONE (SICUREZZA) ---

function generateUUID() { return Utilities.getUuid(); }

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

// --- CORE: GESTIONE SESSIONE (SICUREZZA & PERFORMANCE) ---

// INIZIO MODIFICA
function verifySessionAndGetUser(token) {
  if (!token) throw new Error("Sessione non valida. Effettua nuovamente il login.");

  // 1. PROVA A LEGGERE DALLA CACHE VELOCE
  var cache = CacheService.getScriptCache();
  var cachedUser = cache.get("SESSION_" + token);
  
  if (cachedUser) {
    return JSON.parse(cachedUser);
  }

  // 2. FALLBACK: SE NON IN CACHE, LEGGI IL FOGLIO (LENTO)
  var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
  var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
  var data = sheetCred.getDataRange().getValues();
  
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][COL_MAP.CRED.SESSION_ID]) === token) {
      if (data[i][COL_MAP.CRED.STATO] !== 'ATTIVO') throw new Error("Utenza disabilitata.");
      
      // Update Heartbeat (opzionale: fallo meno spesso per performance, qui lo lasciamo per sicurezza)
      try { sheetCred.getRange(i + 1, COL_MAP.CRED.LAST_LOGIN + 1).setValue(new Date()); } catch(e){}

      var userObj = {
        rowIndex: i + 1,
        username: data[i][COL_MAP.CRED.USERNAME],
        istituzioneId: data[i][COL_MAP.CRED.ISTITUZIONE_ID],
        ruolo: data[i][COL_MAP.CRED.RUOLO],
        nome: data[i][COL_MAP.CRED.NOME],
        cognome: data[i][COL_MAP.CRED.COGNOME]
      };

      // 3. SALVA IN CACHE PER 20 MINUTI (1200 secondi)
      // Così le prossime chiamate non leggeranno il foglio
      cache.put("SESSION_" + token, JSON.stringify(userObj), 1200);

      return userObj;
    }
  }
  throw new Error("Sessione scaduta o invalida.");
}

// INIZIO MODIFICA
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
      role: userCtx.ruolo, // Mappa 'ruolo' su 'role' per il frontend
      nome: userCtx.nome,
      cognome: userCtx.cognome,
      istituzioneId: userCtx.istituzioneId
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
        if (targetUser[COL_MAP.CRED.STATO] !== 'ATTIVO') {
          return { success: false, message: "Utenza in attesa di approvazione d parte del Ministero." };
        }
      } else { 
        return { success: false, message: "Password errata." };
      }
    } else {
       return { success: false, message: "Utente non trovato." };
    }

    var newSessionId = generateUUID();

    // 2. Acquisizione del Lock SOLO per la scrittura
    var lock = LockService.getScriptLock();
    try {
      lock.waitLock(15000); // Timeout ridotto a 15s perché l'operazione è istantanea
      
      sheetCred.getRange(targetRowIndex, COL_MAP.CRED.SESSION_ID + 1).setValue(newSessionId);
      sheetCred.getRange(targetRowIndex, COL_MAP.CRED.LAST_LOGIN + 1)
               .setValue(new Date())
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
      istituzioneId: targetUser[COL_MAP.CRED.ISTITUZIONE_ID]
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
      
      // Lookup O(1) con TextFinder per minimizzare il tempo di lock
      const finder = sheetResp.getRange("B:B").createTextFinder(idIstituzione).matchEntireCell(true);
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
  var lock = LockService.getScriptLock();
  try {
      lock.waitLock(10000);
      var userCtx = verifySessionAndGetUser(token);
      if (String(userCtx.ruolo).toUpperCase() !== 'ADMIN') throw new Error("Non autorizzato.");
      
      var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
      var sheet = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
      var data = sheet.getDataRange().getValues();
      
      var found = false;
      for (var i = 1; i < data.length; i++) {
          if (String(data[i][COL_MAP.CRED.ID]) === String(userId)) {
              var newState = (action === 'APPROVE') ? 'ATTIVO' : 'RIFIUTATO';
              sheet.getRange(i + 1, COL_MAP.CRED.STATO + 1).setValue(newState);
              found = true;
              break;
          }
      }
      if(!found) throw new Error("Utente non trovato.");
      
      SpreadsheetApp.flush();
      return { success: true, message: "Stato utente aggiornato a: " + (action === 'APPROVE' ? 'ATTIVO' : 'RIFIUTATO') };
  } catch(e) {
      return { success: false, message: "Errore: " + e.message };
  } finally {
      lock.releaseLock();
  }
}
// FINE MODIFICA

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
      // Check flessibile sul CF
      if (String(dataAnag[i][0]) === String(foundIdIstituzione) && String(dataAnag[i][1]).toUpperCase().trim().replace(/\s+/g, '') === inputCF) {
        
        var dbNome = String(dataAnag[i][2]).toUpperCase().trim().replace(/\s+/g, ' ');
        var dbCognome = String(dataAnag[i][3]).toUpperCase().trim().replace(/\s+/g, ' ');
        
// INIZIO MODIFICA
        // Confronto più permissivo: controlla se la stringa DB "contiene" l'input o viceversa, oppure uguaglianza esatta
        // Questo aiuta se nel DB è "Mario Antonio" e l'utente scrive "Mario"
        var nameMatch = (dbNome === inputNome); 
        var surnameMatch = (dbCognome === inputCognome);

        if (!nameMatch || !surnameMatch) {
            // Log per debug (opzionale)
            Logger.log("Mismatch Anagrafica: DB[" + dbNome + " " + dbCognome + "] vs INPUT[" + inputNome + " " + inputCognome + "]");
            return { success: false, message: "Il Nominativo inserito non corrisponde esattamente all'anagrafica (" + dbNome + " " + dbCognome + ")." };
        }
        userWhitelist = { 
            idIstituzione: String(dataAnag[i][0]), cf: inputCF, 
            nome: dataAnag[i][2], cognome: dataAnag[i][3], ruolo: dataAnag[i][4] 
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
    
    var salt = generateUUID();
    var passwordHash = hashPassword(formObject.password, salt);
    sheetCred.appendRow([
        generateUUID(), userWhitelist.cf, userWhitelist.idIstituzione, userWhitelist.nome, userWhitelist.cognome, 
        String(formObject.email).trim(), passwordHash, salt, userWhitelist.ruolo, pin, '', 
        'IN_ATTESA_DI_APPROVAZIONE', new Date(), '', '', '', ''
    ]);
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
        return { success: false, message: "Dati utente non trovati." };
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
 * TRIGGER NOTTURNO (Sincronizzazione Export)
 * Da impostare tra le 23:00 e le 00:00.
 * Rigenera completamente il foglio EXPORT_DATI_CESSAZIONI basandosi sui dati JSON.
 */
function syncExportTable() {
  var lock = LockService.getScriptLock();
  try { 
    lock.waitLock(5000);
  } catch(e) { return; } 
  
  try {
    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_CESSAZIONI);
    var sheetResp = ss.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_RESP);
    var sheetExp = ss.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_EXP);
    
    if(!sheetResp || !sheetExp) {
      Logger.log("Fogli non trovati per syncExportTable");
      return;
    }

    // 1. Lettura massiva delle risposte
    var dataResp = sheetResp.getDataRange().getValues();
    var exportRows = [];
    var dataExport = new Date();

    // Elaborazione dati (Parsing JSON)
    for (var i = 1; i < dataResp.length; i++) {
      var idIst = dataResp[i][1]; // Colonna B
      var stato = dataResp[i][2]; // Colonna C
      var rawJson = dataResp[i][5]; // Colonna F
      
      // Filtro: Estrae SOLO i moduli in stato INVIATO
      if (stato === 'INVIATO' && rawJson) {
        try {
          var parsed = JSON.parse(rawJson);
          var rows = Array.isArray(parsed) ? parsed : (parsed.rows || []);
          var flagNuova = (parsed.flag === true) ? "SI" : "NO";

          rows.forEach(function(r) {
            exportRows.push([
              idIst,           
              r.cf,            
              r.azione,        
              r.note || "",    
              dataExport,      // Timestamp univoco di questa sincronizzazione
              flagNuova        
            ]);
          });
        } catch(e) {
          Logger.log("Errore parsing JSON alla riga " + (i+1) + ": " + e.message);
        }
      }
    }
    
    // 2. Pulizia tabella Export (Drop dei dati vecchi, preservando la riga di intestazione)
    var lastRowExp = Math.max(sheetExp.getLastRow(), 1);
    if (lastRowExp > 1) {
      // Pulisce rigorosamente tutte le righe sotto l'intestazione
      sheetExp.getRange(2, 1, lastRowExp - 1, sheetExp.getLastColumn()).clearContent();
    }

    // 3. Scrittura Massiva (Full Refresh) in una singola transazione O(1)
    if (exportRows.length > 0) {
      sheetExp.getRange(2, 1, exportRows.length, exportRows[0].length).setValues(exportRows);
      Logger.log("Export Full Refresh completato: " + exportRows.length + " righe scritte coerentemente.");
    } else {
      Logger.log("Export Full Refresh: Nessun dato valido trovato per l'export.");
    }

    // Eliminata la logica fallace del Watermark (PropertiesService)

  } catch(e) {
    Logger.log("Errore Critico SyncExport: " + e.toString());
  } finally {
    lock.releaseLock();
  }
}