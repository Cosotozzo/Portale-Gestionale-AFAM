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
  "SHEET_CESSAZIONI_EXP": "EXPORT_DATI_CESSAZIONI"
};

// Mappa delle colonne centralizzata
var COL_MAP = {
  CRED: {
    ID: 0, CF: 1, ISTITUZIONE_ID: 2, NOME: 3, COGNOME: 4, USERNAME: 5,
    HASH: 6, SALT: 7, RUOLO: 8, PIN: 9, STATO: 11, SESSION_ID: 14, LAST_LOGIN: 15
  },
  ANAG_CESS: {
    ID_CESSAZIONE: 0, ID_ISTITUZIONE: 1, NOME: 3, COGNOME: 4, CF: 5, DATA_NASCITA: 6
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

function verifySessionAndGetUser(token) {
  if (!token) throw new Error("Sessione non valida. Effettua nuovamente il login.");
  var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
  var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
  var data = sheetCred.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][COL_MAP.CRED.SESSION_ID]) === token) {
      if (data[i][COL_MAP.CRED.STATO] !== 'ATTIVO') throw new Error("Utenza disabilitata.");
      // Update Heartbeat
      sheetCred.getRange(i + 1, COL_MAP.CRED.LAST_LOGIN + 1).setValue(new Date());
      return {
        rowIndex: i + 1,
        username: data[i][COL_MAP.CRED.USERNAME],
        istituzioneId: data[i][COL_MAP.CRED.ISTITUZIONE_ID],
        ruolo: data[i][COL_MAP.CRED.RUOLO],
        nome: data[i][COL_MAP.CRED.NOME],
        cognome: data[i][COL_MAP.CRED.COGNOME]
      };
    }
  }
  throw new Error("Sessione scaduta o invalida.");
}

// --- LOGIN ---

/**
 * Gestisce l'autenticazione utente con protezione per accessi simultanei massivi.
 * @param {Object} formObject Oggetto contenente username e password dal client.
 */
function doLogin(formObject) {
  // Acquisizione del Lock a livello di Script per gestire la coda di 100+ utenze
  var lock = LockService.getScriptLock();
  
  try {
    // Attende fino a 30 secondi che si liberi il semaforo di scrittura
    lock.waitLock(30000); 
    Logger.log("Lock acquisito per login: " + formObject.username);

    var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
    var data = sheetCred.getDataRange().getValues();
    
    var usernameInput = String(formObject.username).trim();
    var passwordInput = formObject.password;

    // Ricerca dell'utente nel database (Sheet CREDENZIALI)
    for (var i = 1; i < data.length; i++) {
      var dbUser = String(data[i][COL_MAP.CRED.USERNAME]).trim();

      if (dbUser === usernameInput) { 
        var storedHash = data[i][COL_MAP.CRED.HASH];
        var salt = data[i][COL_MAP.CRED.SALT];

        // Validazione Password (ES6+)
        if (hashPassword(passwordInput, salt) === storedHash) {
          
          // Verifica stato utenza (Zero Trust)
          if (data[i][COL_MAP.CRED.STATO] !== 'ATTIVO') {
            return { success: false, message: "Utenza non attiva o in attesa di approvazione." };
          }

          // Generazione Sessione Atomica
          var newSessionId = generateUUID();
          
          // Scrittura dati sessione e heartbeat
          // Utilizziamo indici COL_MAP per manutenibilità 
          sheetCred.getRange(i + 1, COL_MAP.CRED.SESSION_ID + 1).setValue(newSessionId);
          sheetCred.getRange(i + 1, COL_MAP.CRED.LAST_LOGIN + 1)
                   .setValue(new Date())
                   .setNumberFormat("dd/MM/yyyy HH:mm:ss");
          
          // Sincronizzazione forzata prima del rilascio del lock
          SpreadsheetApp.flush();
          
          Logger.log("Login completato con successo per: " + dbUser);
          
          return {
            success: true, 
            token: newSessionId, 
            username: dbUser,
            role: data[i][COL_MAP.CRED.RUOLO], 
            nome: data[i][COL_MAP.CRED.NOME], 
            cognome: data[i][COL_MAP.CRED.COGNOME], 
            istituzioneId: data[i][COL_MAP.CRED.ISTITUZIONE_ID]
          };
        } else { 
          return { success: false, message: "Password errata." };
        }
      }
    }
    return { success: false, message: "Utente non trovato." };

  } catch (e) {
    Logger.log("ERRORE CRITICO LOGIN: " + e.message);
    return { 
      success: false, 
      message: "Il server è al momento sovraccarico. Riprova tra pochi istanti." 
    };
  } finally {
    // Rilascio fondamentale del lock per permettere l'accesso agli altri utenti in coda
    lock.releaseLock();
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
    var ssAuth = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    var sheetIst = ssAuth.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
    var dataIst = sheetIst.getDataRange().getValues();
    
    var denominazioneUfficiale = "Istituzione";
    for(var k=1; k<dataIst.length; k++) {
      if(String(dataIst[k][0]).trim() === idIstituzione) { 
        denominazioneUfficiale = dataIst[k][1];
        break;
      }
    }

    var ssCess = SpreadsheetApp.openById(DB_CONFIG.ID_CESSAZIONI);
    var sheetAnag = ssCess.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_ANAG);
    
    var today = new Date();
    var currentYear = today.getFullYear();
    var academicYear = (today.getMonth() > 8) ?
        currentYear + "/" + (currentYear + 1) : (currentYear - 1) + "/" + currentYear;

    if (!sheetAnag || sheetAnag.getLastRow() < 2) {
        return { success: true, listaSoggetti: [], statoModulo: 'NON_COMPILATO', denominazione: denominazioneUfficiale, aa: academicYear, richiestaNuovaFinestra: false };
    }

    var dataAnag = sheetAnag.getDataRange().getValues(); 
    var listaSoggetti = [];

    // Costruzione Lista Soggetti da Anagrafica
    for(var i=1; i<dataAnag.length; i++) {
      if(!dataAnag[i][0]) continue;
      // Filtro per ID Istituzione dell'utente loggato
      if(String(dataAnag[i][COL_MAP.ANAG_CESS.ID_ISTITUZIONE]).trim() === idIstituzione) {
        var eta = "N/D";
        var dataNascitaRaw = dataAnag[i][COL_MAP.ANAG_CESS.DATA_NASCITA];
        var dataNascitaStr = formatDateSafe(dataNascitaRaw); 

        try {
           if (dataNascitaRaw instanceof Date) { 
             eta = currentYear - dataNascitaRaw.getFullYear();
           }
        } catch(e) {}

        listaSoggetti.push({
          idCessazione: String(dataAnag[i][COL_MAP.ANAG_CESS.ID_CESSAZIONE]),
          cf: String(dataAnag[i][COL_MAP.ANAG_CESS.CF]).toUpperCase().trim(),
          nome: String(dataAnag[i][COL_MAP.ANAG_CESS.NOME]),
          cognome: String(dataAnag[i][COL_MAP.ANAG_CESS.COGNOME]),
          dataNascita: dataNascitaStr,
          eta: eta, 
          azione: null, 
          note: ""
        });
      }
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
  var lock = LockService.getScriptLock();
  // Timeout esteso a 30s per gestire le code nei momenti di picco
  try { lock.waitLock(30000); } catch (e) {
    return { success: false, message: "Server intenso traffico. Riprova tra 10 secondi." };
  }

  try {
    // 1. Verifica Sicurezza
    var userCtx = verifySessionAndGetUser(token);
    var idIstituzione = String(userCtx.istituzioneId);
    var usernameReale = userCtx.username;

    var ssCess = SpreadsheetApp.openById(DB_CONFIG.ID_CESSAZIONI);
    var sheetResp = ssCess.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_RESP);
    
    // 2. Validazione Logica (Solo se invio definitivo)
    if(payload.mode === 'FINAL') {
      for(var j=0; j<payload.rows.length; j++) {
        if(!payload.rows[j].azione) throw new Error("Devi validare tutte le righe prima di inviare.");
        if(payload.rows[j].azione === 'MODIFICA' && (!payload.rows[j].note || payload.rows[j].note.trim() === "")) {
             throw new Error("Nota obbligatoria per le modifiche.");
        }
      }
    }
    
    // 3. Preparazione Dati
    var nuovoStato = (payload.mode === 'FINAL') ? 'INVIATO' : 'BOZZA';
    var dataOperazione = new Date();
    // Prepariamo il pacchetto JSON (Rows + Flag Nuova Finestra)
    var fullDataToStore = {
      rows: payload.rows,
      flag: payload.richiestaNuovaFinestra === true
    };
    var jsonString = JSON.stringify(fullDataToStore);
    
    // 4. RICERCA VELOCE (TextFinder)
    // Cerca l'ID Istituzione nella Colonna B (Indice 2) senza caricare tutti i dati
    var finder = sheetResp.getRange("B:B").createTextFinder(idIstituzione).matchEntireCell(true);
    var result = finder.findNext();
    
    if (result) {
      // --> CASO AGGIORNAMENTO (Upsert)
      var rowIndex = result.getRow();
      // Scrive solo nelle colonne: Stato(C), Data(D), Utente(E), JSON(F)
      sheetResp.getRange(rowIndex, 3, 1, 4).setValues([[nuovoStato, dataOperazione, usernameReale, jsonString]]);
    } else {
      // --> CASO NUOVO INSERIMENTO
      var idRisposta = Utilities.getUuid();
      sheetResp.appendRow([idRisposta, idIstituzione, nuovoStato, dataOperazione, usernameReale, jsonString]);
    }
    
    // Scrittura immediata
    SpreadsheetApp.flush();
    
    return { 
        success: true, 
        message: payload.mode === 'FINAL' 
            ? "Invio completato e protocollato." 
            : "Bozza salvata correttamente.",
        lastSave: new Date()
    };

  } catch(e) {
    Logger.log("Errore Save: " + e.message);
    return { success: false, message: "Errore salvataggio: " + e.message };
  } finally {
    lock.releaseLock();
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
    var inputCF = String(formObject.codiceFiscale).toUpperCase().trim();
    var inputNome = String(formObject.nome).toUpperCase().trim();
    var inputCognome = String(formObject.cognome).toUpperCase().trim();
    
    for (var i = 1; i < dataAnag.length; i++) {
      if (String(dataAnag[i][0]) === String(foundIdIstituzione) && String(dataAnag[i][1]).toUpperCase().trim() === inputCF) {
        var dbNome = String(dataAnag[i][2]).toUpperCase().trim();
        var dbCognome = String(dataAnag[i][3]).toUpperCase().trim();
        if (dbNome !== inputNome || dbCognome !== inputCognome) {
            return { success: false, message: "Il Nominativo inserito non corrisponde al Codice Fiscale in anagrafica." };
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
    for (var i = 1; i < dataCred.length; i++) { 
        if (String(dataCred[i][COL_MAP.CRED.CF]).toUpperCase() === userWhitelist.cf) return { success: false, message: "Utente già registrato." }; 
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
    for (var i = 1; i < dataIst.length; i++) { 
        if (String(dataIst[i][1]).trim().toLowerCase() === searchName) { targetIdIst = dataIst[i][0]; break; } 
    }
    if (!targetIdIst) return { success: false, message: "Istituzione non trovata." };

    var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
    var dataCred = sheetCred.getDataRange().getValues();
    var userRowIndex = -1;
    for (var i = 1; i < dataCred.length; i++) {
      if (String(dataCred[i][COL_MAP.CRED.CF]).toUpperCase() === String(formObj.cf).toUpperCase().trim() && 
          String(dataCred[i][COL_MAP.CRED.ISTITUZIONE_ID]) === String(targetIdIst) && 
          String(dataCred[i][COL_MAP.CRED.USERNAME]) == String(formObj.username).trim()) { 
          var storedPin = String(dataCred[i][COL_MAP.CRED.PIN]).trim().toUpperCase();
          var inputPin = String(formObj.pin).trim().toUpperCase();
          if(storedPin !== inputPin) { return { success: false, message: "PIN di sicurezza errato." }; }
          userRowIndex = i + 1; break;
      }
    }
    if (userRowIndex === -1) return { success: false, message: "Dati utente non trovati." };
    
    var newSalt = generateUUID();
    var newHash = hashPassword(formObj.newPassword, newSalt);
    sheetCred.getRange(userRowIndex, COL_MAP.CRED.HASH + 1).setValue(newHash);
    sheetCred.getRange(userRowIndex, COL_MAP.CRED.SALT + 1).setValue(newSalt);
    return { success: true, message: "Password aggiornata con successo." };
  } catch(e) { return { success: false, message: "Errore: " + e.toString() }; }
}

function logoutUser(token) {
  try {
     var ss = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
     var sheetCred = ss.getSheetByName(DB_CONFIG.SHEET_CREDENZIALI);
     var data = sheetCred.getDataRange().getValues();
     for (var i = 1; i < data.length; i++) {
       if (String(data[i][COL_MAP.CRED.SESSION_ID]) === token) {
         sheetCred.getRange(i + 1, COL_MAP.CRED.SESSION_ID + 1).setValue("");
         return true;
       }
     }
  } catch(e) {}
}

/**
 * TRIGGER NOTTURNO (Sincronizzazione Export)
 * Da impostare tra le 23:00 e le 00:00.
 * Rigenera completamente il foglio EXPORT_DATI_CESSAZIONI basandosi sui dati JSON.
 */
function syncExportTable() {
  var lock = LockService.getScriptLock();
  // Se il processo è già in corso (improbabile di notte), usciamo subito
  try { lock.waitLock(5000); } catch(e) { return; } 
  
  try {
    var ss = SpreadsheetApp.openById(DB_CONFIG.ID_CESSAZIONI);
    var sheetResp = ss.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_RESP);
    var sheetExp = ss.getSheetByName(DB_CONFIG.SHEET_CESSAZIONI_EXP);
    
    if(!sheetResp || !sheetExp) {
      Logger.log("Fogli non trovati per syncExportTable");
      return;
    }

    // 1. Lettura massiva di tutte le risposte
    var dataResp = sheetResp.getDataRange().getValues();
    var exportRows = [];
    
    // 2. Elaborazione dati (Parsing JSON)
    // Parte da i=1 per saltare l'intestazione
    for (var i = 1; i < dataResp.length; i++) {
      var idIst = dataResp[i][1];     // Colonna B
      var stato = dataResp[i][2];     // Colonna C
      var rawJson = dataResp[i][5];   // Colonna F
      
      // Elaboriamo SOLO le pratiche INVIATO (ignoriamo le BOZZE)
      if (stato === 'INVIATO' && rawJson && rawJson !== "") {
        try {
          var parsed = JSON.parse(rawJson);
          
          // Compatibilità: gestisce sia il vecchio formato array [] sia il nuovo oggetto {rows, flag}
          var rows = Array.isArray(parsed) ? parsed : (parsed.rows || []);
          var flagNuova = (parsed.flag === true) ? "SI" : "NO";
          
          // Creiamo una riga export per ogni soggetto nella cessazione
          rows.forEach(function(r) {
            exportRows.push([
              idIst,           // ID Istituzione
              r.cf,            // Codice Fiscale
              r.azione,        // Azione (APPROVA/RIFIUTA/ECC)
              r.note || "",    // Note
              new Date(),      // Data di questo export
              flagNuova        // Richiesta nuova finestra (SI/NO)
            ]);
          });
        } catch(e) {
          Logger.log("Errore parsing JSON alla riga " + (i+1) + ": " + e.message);
        }
      }
    }
    
    // 3. Scrittura Massiva (Cancella e Riscrivi)
    sheetExp.clearContents();
    // Reinseriamo l'intestazione
    sheetExp.appendRow(["ID_ISTITUZIONE", "CF", "AZIONE", "NOTE", "DATA_EXPORT", "RICHIESTA_NUOVA_FINESTRA"]);
    
    if (exportRows.length > 0) {
      // Scrive tutte le righe in un colpo solo
      sheetExp.getRange(2, 1, exportRows.length, 6).setValues(exportRows);
    }
    
    Logger.log("Export completato: " + exportRows.length + " righe generate.");
    
  } catch(e) {
    Logger.log("Errore Critico SyncExport: " + e.toString());
  } finally {
    lock.releaseLock();
  }
}

/**
 * FUNZIONE DI TEST SINCRONIZZAZIONE
 * Questo è un commento per verificare che Gemini legga l'ultima versione.
 */
function testSincronizzazioneGemini() {
  Logger.log("Sincronizzazione completata con successo!");
  return "Il collegamento GitHub-Gemini funziona!";
}