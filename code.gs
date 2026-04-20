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
  "SHEET_BUDGET_TRANS": "BUDGET_TRANS",
  "SHEET_BUDGET_EXP": "BUDGET_EXP"
};

// Mappa delle colonne centralizzata
var COL_MAP = {
  CRED: {
    ID: 0, CF: 1, ISTITUZIONE_ID: 2, NOME: 3, COGNOME: 4, USERNAME: 5,
    HASH: 6, SALT: 7, RUOLO: 8, PIN: 9, STATO: 11, SESSION_ID: 14, LAST_LOGIN: 15, ACCETTAZIONE_PRIVACY: 16, ACCETTAZIONE_COOKIE: 17
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
    ID_ACQUIRENTE: 4, DENOM_ACQUIRENTE: 5, RESIDUO_ANTE_ACQ: 6, RESIDUO_POST_ACQ: 7, VALORE_SCAMB: 8, ID_TRANS: 9
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

function verifySessionAndGetUser(token) {
  if (!token) throw new Error("Sessione non valida. Effettua nuovamente il login.");
  
  // 1. PROVA A LEGGERE DALLA CACHE VELOCE
  const cache = CacheService.getScriptCache();
  const cachedUser = cache.get("SESSION_" + token);
  if (cachedUser) {
    return JSON.parse(cachedUser);
  }

  // 2. FALLBACK: SE NON IN CACHE, USA TEXTFINDER (VELOCE)
  const ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
  const sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
  
  // TextFinder mirato sulla colonna SESSION_ID
  const finder = sheetCred.getRange(1, COL_MAP.CRED.SESSION_ID + 1, sheetCred.getLastRow(), 1)
                          .createTextFinder(token)
                          .matchEntireCell(true);
  const result = finder.findNext();
  
  if (result) {
    const rowIndex = result.getRow();
    const rowData = sheetCred.getRange(rowIndex, 1, 1, sheetCred.getLastColumn()).getValues()[0];
    
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
    // 3. SALVA IN CACHE PER 20 MINUTI (1200 secondi)
    cache.put("SESSION_" + token, JSON.stringify(userObj), 1200);
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
    
    var salt = generateUUID();
    var passwordHash = hashPassword(formObject.password, salt);
// Formattiamo la data del momento esatto per il tracciato DB
    var timestampConsenso = Utilities.formatDate(new Date(), "Europe/Rome", "dd/MM/yyyy HH:mm:ss");
    var privacyLog = formObject.privacyConsent ? "ACCETTATO - " + timestampConsenso : "NON ACCETTATO";
    var cookieLog = formObject.cookieConsent ? "ACCETTATO - " + timestampConsenso : "NON ACCETTATO";

    // Salvataggio: Mappiamo Privacy su Colonna Q (17) e Cookie su Colonna R (18)
    sheetCred.appendRow([
        generateUUID(), userWhitelist.cf, userWhitelist.idIstituzione, userWhitelist.nome, userWhitelist.cognome, 
        String(formObject.email).trim(), passwordHash, salt, userWhitelist.ruolo, pin, '', 
        'IN_ATTESA_DI_APPROVAZIONE', new Date(), '', '', '', privacyLog, cookieLog
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

/**
 * API RPC: Gestisce l'invio di una nuova richiesta di budget.
 * Il JSON_Blob viene strutturato qui lato server garantendo il logging completo.
 */
function submitBudgetRequest(token, payload) {
var lock = LockService.getScriptLock();
  try {
    var userCtx = verifySessionAndGetUser(token);
    var idRichiedente = String(userCtx.istituzioneId);
    var idCedente = String(payload.cedenteId).trim();

    // Pessimistic Locking come da Specifica (Cap 5)
    if (!lock.tryLock(5000)) {
      throw new Error("Il sistema è momentaneamente occupato. Riprovare.");
    }

    var importo = parseFloat(payload.importo);
    if (isNaN(importo) || importo <= 0) {
        throw new Error("Importo non valido.");
    }

    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGET);
    var sheetBase = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
    var sheetTrans = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);

    // Guardia Zero Trust: evita errori cryptici di appendRow su null
    if (!sheetBase || !sheetTrans) {
        throw new Error("Errore DB: Impossibile trovare i fogli. Verifica che i fogli " + DB_CONFIG.SHEET_BUDGET_BASE + " e " + DB_CONFIG.SHEET_BUDGET_TRANS + " esistano nel Google Sheet.");
    }

    // --- CALCOLO SALDO CEDENTE IN TEMPO REALE (Sotto Lock) ---
    var baseData = sheetBase.getDataRange().getValues();
    var budgetInizialeCedente = 0;
    
    for (var i = 1; i < baseData.length; i++) {
        if (String(baseData[i][COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]).trim() === idCedente) {
            budgetInizialeCedente = parseFloat(baseData[i][COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0;
            break;
        }
    }

    var transData = sheetTrans.getLastRow() > 1 ? sheetTrans.getDataRange().getValues() : [];
    var usciteCedente = 0;
    var entrateCedente = 0;

    for (var t = 1; t < transData.length; t++) {
        var tReqId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
        var tCedId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
        var tStato = transData[t][COL_MAP.BUDGET_TRANS.STATO];
        
        var tPayloadRaw = transData[t][COL_MAP.BUDGET_TRANS.JSON_BLOB];
        var tPayload = {};
        try { tPayload = JSON.parse(tPayloadRaw); } catch(e){}
        var tImporto = parseFloat(tPayload.importo_richiesto) || 0;

        // Entrate: Il cedente ha a sua volta acquisito fondi da altri (stato ACCETTATA)
        if (tReqId === idCedente && tStato === 'ACCETTATA') {
            entrateCedente += tImporto;
        }
        
        // Uscite: Il cedente sta cedendo o ha ceduto fondi
        if (tCedId === idCedente && (tStato === 'ACCETTATA' || tStato === 'INVIATA' || tStato === 'IN_INTEGRAZIONE')) {
            usciteCedente += tImporto;
        }
    }

    var saldoDisponibileCedente = budgetInizialeCedente + entrateCedente - usciteCedente;

    // --- VERIFICA CAPIENZA ---
    if (importo > saldoDisponibileCedente) {
        throw new Error("Fondi insufficienti/già prenotati da altri enti.");
    }

    // --- SALVATAGGIO TRANSAZIONE ---
    var now = new Date().toISOString();
    
    var dataBlob = {
      importo_richiesto: importo,
      history: [
        {
          timestamp: now,
          attore: idRichiedente,
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

  } catch (e) {
    Logger.log("Errore submitBudgetRequest: " + e.message);
    throw new Error(e.message);
  } finally {
    lock.releaseLock();
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
    
    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGET);
    var sheetBase = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
    var sheetTrans = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    
    // 1. Lettura Anagrafica e Budget Base
    var baseData = sheetBase ? sheetBase.getDataRange().getValues() : [];
    var mapIstituzioni = {}; 
    var listIstituzioni = [];
    
    for(var i=1; i<baseData.length; i++) {
        var id = String(baseData[i][COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]).trim();
        var nome = baseData[i][COL_MAP.BUDGET_BASE.DENOMINAZIONE];
        var budgetBase = parseFloat(baseData[i][COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0;
        mapIstituzioni[id] = { nome: nome, budgetBase: budgetBase };
        if(id !== myIstId) listIstituzioni.push({id: id, nome: nome});
    }

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
 * API RPC: Permette al Ministero di annullare un'operazione precedentemente accettata.
 * Calcola in tempo reale la capienza per prevenire scoperti in caso di annullamenti non sequenziali.
 */
function annullaTransazioneMinistero(token, idTrans) {
  var lock = LockService.getScriptLock();
  try {
    var userCtx = verifySessionAndGetUser(token);
    var ruolo = String(userCtx.ruolo).toUpperCase().trim();
    if (ruolo !== 'ADMIN' && ruolo !== 'MINISTERO') throw new Error("Azione non consentita.");

    if (!lock.tryLock(15000)) throw new Error("Il sistema è momentaneamente occupato. Riprovare.");

    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGET);
    var sheetTrans = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    var transData = sheetTrans.getDataRange().getValues();
    
    var targetRowIdx = -1;
    var transazione = null;
    
    // Ricerca della transazione
    for (var i = 1; i < transData.length; i++) {
        if (String(transData[i][COL_MAP.BUDGET_TRANS.ID_TRANS]) === String(idTrans)) {
            targetRowIdx = i + 1;
            transazione = transData[i];
            break;
        }
    }
    
    if (targetRowIdx === -1) throw new Error("Transazione non trovata.");
    if (transazione[COL_MAP.BUDGET_TRANS.STATO] !== 'ACCETTATA') throw new Error("Solo le operazioni ACCETTATE possono essere riaperte.");
    
    var reqId = String(transazione[COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
    var payloadRaw = transazione[COL_MAP.BUDGET_TRANS.JSON_BLOB];
    var payload = JSON.parse(payloadRaw);
    var importo = parseFloat(payload.importo_richiesto);
    
    // VALIDAZIONE SEQUENZIALE: Ricalcolo Saldo Attuale del Richiedente (Colui che ha ricevuto i fondi)
    var sheetBase = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
    var baseData = sheetBase.getDataRange().getValues();
    var reqBudgetBase = 0;
    
    for(var b = 1; b < baseData.length; b++) {
        if(String(baseData[b][COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]).trim() === reqId) {
            reqBudgetBase = parseFloat(baseData[b][COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0;
            break;
        }
    }
    
    var reqCurrentBalance = reqBudgetBase;
    
    for (var t = 1; t < transData.length; t++) {
        if (transData[t][COL_MAP.BUDGET_TRANS.STATO] === 'ACCETTATA') {
            var tReqId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]).trim();
            var tCedId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_CEDENTE]).trim();
            var tPayload = JSON.parse(transData[t][COL_MAP.BUDGET_TRANS.JSON_BLOB]);
            var tImporto = parseFloat(tPayload.importo_richiesto) || 0;
            
            if (tReqId === reqId) reqCurrentBalance += tImporto;
            if (tCedId === reqId) reqCurrentBalance -= tImporto;
        }
    }
    
    // Check Critico: Se annullare questa operazione manda il ricevente sotto zero
    if ((reqCurrentBalance - importo) < 0) {
        Logger.log("[SECURITY] Annullamento bloccato per Scoperto di Bilancio. Istituzione ID: " + reqId);
        throw new Error("La riapertura deve essere sequenziale dall'ultima operazione fino alla prima.");
    }
    
    // Scrittura aggiornamento
    var now = new Date().toISOString();
    payload.history.push({
        timestamp: now,
        attore: userCtx.username,
        ruolo_attore: ruolo,
        azione: "ANNULLAMENTO_MINISTERO",
        note: "Operazione annullata dal Ministero per riapertura termini."
    });
    
    sheetTrans.getRange(targetRowIdx, COL_MAP.BUDGET_TRANS.STATO + 1).setValue("ANNULLATA_MINISTERO");
    sheetTrans.getRange(targetRowIdx, COL_MAP.BUDGET_TRANS.JSON_BLOB + 1).setValue(JSON.stringify(payload));
    
    Logger.log("[AUDIT] Transazione " + idTrans + " annullata dal Ministero (" + userCtx.username + ")");
    SpreadsheetApp.flush();
    
    return { success: true };
    
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

    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGET);
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

    const ss = SpreadsheetApp.openById(DB_CONFIG.ID_BUDGET);
    const sheet = ss.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    const data = sheet.getDataRange().getValues();

    let rowIndex = -1;
    let transazione = null;

    // 3. Ricerca Transazione
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][COL_MAP.BUDGET_TRANS.ID_TRANS]) === String(id)) {
        rowIndex = i + 1;
        transazione = data[i];
        break;
      }
    }

    if (rowIndex === -1) throw new Error("Transazione non trovata nel database.");

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
 * Job Notturno: Sincronizzazione Export Budget (BUDGET_TRANS -> BUDGET_EXP).
 * Ottimizzato con Early Exit (Timestamp) e inserimento incrementale.
 */
function syncBudgetExportTable() {
  const lock = LockService.getScriptLock();
  try {
    // Zero Trust: Timeout 30s per concorrenza
    if (!lock.tryLock(30000)) {
      Logger.log("[JOB BUDGET] Impossibile acquisire il lock. Job saltato.");
      return;
    }

    const fileBudget = DriveApp.getFileById(DB_CONFIG.ID_BUDGET);
    const lastModifiedTime = fileBudget.getLastUpdated().getTime();
    
    const scriptProperties = PropertiesService.getScriptProperties();
    const lastSyncTime = parseInt(scriptProperties.getProperty('BUDGET_LAST_SYNC_TIME')) || 0;

    // Early Exit: fermiamo il job se il file non è stato toccato
    if (lastModifiedTime <= lastSyncTime) {
      Logger.log("[JOB BUDGET] Nessuna modifica rilevata al DB Budget dall'ultima esecuzione. Early Exit.");
      return;
    }

    const ssBudget = SpreadsheetApp.open(fileBudget);
    const sheetBase = ssBudget.getSheetByName(DB_CONFIG.SHEET_BUDGET_BASE);
    const sheetTrans = ssBudget.getSheetByName(DB_CONFIG.SHEET_BUDGET_TRANS);
    const sheetExp = ssBudget.getSheetByName(DB_CONFIG.SHEET_BUDGET_EXP);

    // 1. Caricamento Anagrafica e Saldi
    const baseData = sheetBase.getDataRange().getValues();
    const mapBalances = {};
    const mapNames = {};
    for (let b = 1; b < baseData.length; b++) {
      const id = String(baseData[b][COL_MAP.BUDGET_BASE.ID_ISTITUZIONE]);
      mapBalances[id] = parseFloat(baseData[b][COL_MAP.BUDGET_BASE.BUDGET_INIZIALE]) || 0;
      mapNames[id] = baseData[b][COL_MAP.BUDGET_BASE.DENOMINAZIONE];
    }

    // 2. Recupero ID_TRANS già esportati
    const lastRowExp = sheetExp.getLastRow();
    const exportedIds = new Set();
    if (lastRowExp > 1) {
      // Assumendo che ID_TRANS sia alla colonna J (Indice 9, quindi colonna 10 del foglio)
      const existingIds = sheetExp.getRange(2, COL_MAP.BUDGET_EXP.ID_TRANS + 1, lastRowExp - 1, 1).getValues();
      existingIds.forEach(row => exportedIds.add(String(row[0])));
    }

// 3. Elaborazione sequenziale transazioni
    const transData = sheetTrans.getDataRange().getValues();
    const rowsToExport = [];

    for (let t = 1; t < transData.length; t++) {
      const idTrans = String(transData[t][COL_MAP.BUDGET_TRANS.ID_TRANS]);
      const reqId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_RICHIEDENTE]);
      const cedId = String(transData[t][COL_MAP.BUDGET_TRANS.ID_CEDENTE]);
      const stato = transData[t][COL_MAP.BUDGET_TRANS.STATO];
      
      // FILTRO: Solo scambi confermati
      if (stato !== 'ACCETTATA') continue;

      const payload = JSON.parse(transData[t][COL_MAP.BUDGET_TRANS.JSON_BLOB] || "{}");
      const importo = parseFloat(payload.importo_richiesto) || 0;

      // Cattura residui Ante (Stato prima di questa transazione)
      const anteCed = mapBalances[cedId] || 0;
      const anteReq = mapBalances[reqId] || 0;

      // AGGIORNAMENTO SALDI: Applichiamo l'effetto dello scambio al registro temporaneo
      mapBalances[cedId] -= importo;
      mapBalances[reqId] += importo;

      // Cattura residui Post (Stato dopo questa transazione)
      const postCed = mapBalances[cedId] || 0;
      const postReq = mapBalances[reqId] || 0;

      // IDEMPOTENZA: Aggiungiamo alla lista di scrittura solo se non è già nell'export
      if (!exportedIds.has(idTrans)) {
        rowsToExport.push([
          cedId, 
          mapNames[cedId] || cedId, 
          anteCed, 
          postCed,
          reqId, 
          mapNames[reqId] || reqId, 
          anteReq, 
          postReq,
          importo,
          idTrans 
        ]);
      }
    }

    // 4. Scrittura Massiva Finale
    if (rowsToExport.length > 0) {
      sheetExp.getRange(lastRowExp + 1, 1, rowsToExport.length, rowsToExport[0].length).setValues(rowsToExport);
      SpreadsheetApp.flush();
      Logger.log(`[JOB BUDGET] Success: Esportate ${rowsToExport.length} nuove occorrenze.`);
    } else {
      Logger.log("[JOB BUDGET] Nessuna nuova occorrenza trovata da esportare.");
    }

    // Aggiorna il timestamp di successo
    scriptProperties.setProperty('BUDGET_LAST_SYNC_TIME', new Date().getTime().toString());

  } catch (e) {
    Logger.log("[ERRORE CRITICO JOB BUDGET] " + e.message);
  } finally {
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