// --- INIZIO CREAZIONE NUOVO FILE: BackendRguRca.gs ---

function fetchRguRcaData(token) {
  try {
    const userCtx = verifySessionAndGetUser(token);
    const idIst = String(userCtx.istituzioneId).trim();
    const isMinistero = (String(userCtx.ruolo).toUpperCase() === 'MINISTERO' || String(userCtx.ruolo).toUpperCase() === 'ADMIN');

    if (isMinistero) return fetchMinisteroRguRcaReport(token);

    const ssDb = SpreadsheetApp.openById(DB_CONFIG.ID_RGU_RCA);
    const sheetTrans = ssDb.getSheetByName(DB_CONFIG.SHEET_RGU_RCA_TRANS);
    const transData = sheetTrans ? sheetTrans.getDataRange().getValues() : [];

    const activeNominations = {};
    const storicoList = [];

    // Pattern Event Sourcing per Proiezione Corrente
    for (let i = 1; i < transData.length; i++) {
      if (String(transData[i][1]).trim() !== idIst) continue;

      const idTrans = transData[i][0];
      const stato = transData[i][3];
      const payload = JSON.parse(transData[i][4]);
      payload.ruoloControllato = transData[i][2]; // RGU o RCA

      if (stato === "ATTIVO") {
        payload.idTransazione = idTrans;
        activeNominations[idTrans] = payload;
      } else if (stato === "CESSATO") {
        const originalId = payload.idTransNominaOriginale;
        if (activeNominations[originalId]) {
          const storicized = Object.assign({}, activeNominations[originalId]);
          storicized.dataCessazione = payload.dataCessazione;
          storicized.motivoCessazione = payload.motivoCessazione || "N/A";
          storicoList.push(storicized);
          delete activeNominations[originalId];
        }
      }
    }

    storicoList.sort((a, b) => new Date(b.dataCessazione) - new Date(a.dataCessazione));

    // Estrazione whitelist anagrafica istituzione
    const ssMaster = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    const sheetAnag = ssMaster.getSheetByName(DB_CONFIG.SHEET_ANAGRAFICA);
    const dataAnag = sheetAnag.getDataRange().getValues();
    const whitelist = [];

    for (let i = 1; i < dataAnag.length; i++) {
      if (String(dataAnag[i][0]).trim() === idIst) {
        whitelist.push({
          cf: String(dataAnag[i][1]).trim(),
          nome: String(dataAnag[i][2]).trim(),
          cognome: String(dataAnag[i][3]).trim(),
          profilo: dataAnag[i][5] ? String(dataAnag[i][5]).trim() : "Dato mancante, necessaria verifica"
        });
      }
    }

    return { success: true, isAdmin: false, attivi: activeNominations, storico: storicoList, anagrafica: whitelist, denom: getInstitutionNameById(idIst) };
  } catch (e) {
    return { success: false, message: e.message };
  }
}

function saveRguRcaNominee(token, payload) {
  const lock = LockService.getScriptLock();
  try {
    const userCtx = verifySessionAndGetUser(token);
    const idIst = String(userCtx.istituzioneId).trim();

if (!isRguRcaAttivo() && !['ADMIN', 'MINISTERO'].includes(String(userCtx.ruolo).toUpperCase())) {
      throw new Error("Operazione negata: Il modulo di Gestione RGU/RCA è momentaneamente disabilitato dal Ministero.");
    }

    // Validazione Dominio Server-Side
    if (['Funzionario', 'Assistente'].includes(payload.profiloSelezionato) && payload.flagIncaricoCdaAdInterim !== true) {
      throw new Error("Operazione rifiutata: L'incarico Ad-Interim da parte del CdA è obbligatorio per Funzionari e Assistenti.");
    }
    
    if (payload.profiloSelezionato === 'Docente') {
      if (!payload.qualificaDirettivaDocente || !['Direttore dell\'Istituto', 'Vicedirettore dell\'Istituto'].includes(payload.qualificaDirettivaDocente)) {
        throw new Error("Operazione rifiutata: Per i profili Docente è obbligatorio specificare la qualifica di direzione (Direttore/Vicedirettore) e compilare la nota di giustificazione.");
      }
      if (!payload.notaGiustificativaDocente || payload.notaGiustificativaDocente.length < 10) {
        throw new Error("Operazione rifiutata: Inserire una nota giustificativa valida (min. 10 caratteri) per l'incarico a Docente.");
      }
    }

    if (!lock.tryLock(30000)) throw new Error("Sistema occupato a causa di molti inserimenti simultanei. Riprovare tra 30 secondi.");

    const ssDb = SpreadsheetApp.openById(DB_CONFIG.ID_RGU_RCA);
    const sheetTrans = ssDb.getSheetByName(DB_CONFIG.SHEET_RGU_RCA_TRANS);
    const transData = sheetTrans.getDataRange().getValues();

    // Ricalcolo Capacità (Sotto Lock)
    let countRGU = 0;
    let countRCA = 0;
    const activeMap = {};

    for (let i = 1; i < transData.length; i++) {
      if (String(transData[i][1]).trim() !== idIst) continue;
      const idTrans = transData[i][0];
      const ruolo = transData[i][2];
      const stato = transData[i][3];
      const p = JSON.parse(transData[i][4]);

      if (stato === "ATTIVO") {
        activeMap[idTrans] = ruolo;
      } else if (stato === "CESSATO") {
        delete activeMap[p.idTransNominaOriginale];
      }
    }

    Object.values(activeMap).forEach(r => {
      if (r === 'RGU') countRGU++;
      if (r === 'RCA') countRCA++;
    });

    if (payload.ruoloTarget === 'RGU' && countRGU >= 1) throw new Error("Operazione rifiutata: Risulta già presente un Responsabile Gestione Utenze attivo per questa istituzione. Effettuare la cessazione del soggetto precedente prima di inserire una nuova nomina.");
    if (payload.ruoloTarget === 'RCA' && countRCA >= 2) throw new Error("Operazione rifiutata: Sono già presenti due Responsabili Competenze Accessorie attivi per questa istituzione.");

    const idTransazione = Utilities.getUuid();
    const dataOperazione = new Date();

    const jsonBlob = {
      nome: sanitizeForFormulaInjection(payload.nome),
      cognome: sanitizeForFormulaInjection(payload.cognome),
      codiceFiscale: sanitizeForFormulaInjection(payload.cf),
      profiloSelezionato: sanitizeForFormulaInjection(payload.profiloSelezionato),
      qualificaDirettivaDocente: payload.qualificaDirettivaDocente || "",
      notaGiustificativaDocente: sanitizeForFormulaInjection(payload.notaGiustificativaDocente || ""),
      dataAttivazione: dataOperazione.toISOString(),
      flagIncaricoCdaAdInterim: payload.flagIncaricoCdaAdInterim,
      history: [{ timestamp: dataOperazione.toISOString(), azione: "NOMINA", utente: userCtx.username }]
    };

    sheetTrans.appendRow([
      idTransazione,
      idIst,
      payload.ruoloTarget,
      "ATTIVO",
      JSON.stringify(jsonBlob),
      userCtx.username,
      dataOperazione
    ]);

    SpreadsheetApp.flush();
    return { success: true, message: "Nomina registrata con successo." };

  } catch (e) {
    return { success: false, message: e.message };
  } finally {
    lock.releaseLock();
  }
}

function terminateRguRcaNominee(token, payload) {
  const lock = LockService.getScriptLock();
  try {
    const userCtx = verifySessionAndGetUser(token);
    const idIst = String(userCtx.istituzioneId).trim();

if (!isRguRcaAttivo() && !['ADMIN', 'MINISTERO'].includes(String(userCtx.ruolo).toUpperCase())) {
      throw new Error("Operazione negata: Il modulo di Gestione RGU/RCA è momentaneamente disabilitato dal Ministero.");
    }

    if (!lock.tryLock(30000)) throw new Error("Sistema occupato. Riprovare.");

    const ssDb = SpreadsheetApp.openById(DB_CONFIG.ID_RGU_RCA);
    const sheetTrans = ssDb.getSheetByName(DB_CONFIG.SHEET_RGU_RCA_TRANS);
    
    // Inserimento evento di cessazione (Append-only)
    const dataCess = new Date();
    const jsonBlob = {
      idTransNominaOriginale: payload.idTransNominaOriginale,
      motivoCessazione: sanitizeForFormulaInjection(payload.motivo || "Cessazione standard"),
      dataCessazione: dataCess.toISOString()
    };

    sheetTrans.appendRow([
      Utilities.getUuid(),
      idIst,
      payload.ruoloControllo, // Ereditato dal payload frontend
      "CESSATO",
      JSON.stringify(jsonBlob),
      userCtx.username,
      dataCess
    ]);

    SpreadsheetApp.flush();
    return { success: true, message: "Attività cessata correttamente." };

  } catch (e) {
    return { success: false, message: e.message };
  } finally {
    lock.releaseLock();
  }
}

function fetchMinisteroRguRcaReport(token) {
   // Logica Admin semplificata come da punto 3.4
   const ssAuth = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
   const sheetIst = ssAuth.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);
   const dataIst = sheetIst.getDataRange().getValues();
   
   const ssDb = SpreadsheetApp.openById(DB_CONFIG.ID_RGU_RCA);
   const sheetTrans = ssDb.getSheetByName(DB_CONFIG.SHEET_RGU_RCA_TRANS);
   const transData = sheetTrans ? sheetTrans.getDataRange().getValues() : [];

   const activeMap = {}; // { idIst: { rguCount: 0, rcaCount: 0 } }
   
   for (let i = 1; i < transData.length; i++) {
      const idIst = String(transData[i][1]).trim();
      const ruolo = transData[i][2];
      const stato = transData[i][3];
      const p = JSON.parse(transData[i][4]);
      
      if (!activeMap[idIst]) activeMap[idIst] = { RGU: new Set(), RCA: new Set() };
      
      if (stato === "ATTIVO") {
          activeMap[idIst][ruolo].add(transData[i][0]);
      } else if (stato === "CESSATO") {
          activeMap[idIst]['RGU'].delete(p.idTransNominaOriginale);
          activeMap[idIst]['RCA'].delete(p.idTransNominaOriginale);
      }
   }

   const report = [];
   for (let k = 1; k < dataIst.length; k++) {
       const idIst = String(dataIst[k][0]).trim();
       const denom = dataIst[k][1];
       const rguCount = activeMap[idIst] ? activeMap[idIst].RGU.size : 0;
       const rcaCount = activeMap[idIst] ? activeMap[idIst].RCA.size : 0;
       
       report.push({
           id: idIst,
           denominazione: denom,
           statoRgu: rguCount === 1 ? 'ATTIVO' : 'NON ASSOCIATO',
           statoRca: rcaCount === 2 ? 'ATTIVO' : (rcaCount === 1 ? 'PARZIALE' : 'NON ASSOCIATO')
       });
   }
   
const props = PropertiesService.getScriptProperties();
   const isAttivo = props.getProperty('RGU_RCA_ATTIVO' + CURRENT_ENV.SUFFIX) !== 'FALSE';
   return { success: true, isAdmin: true, reportData: report, isAttivo: isAttivo };
}

function isRguRcaAttivo() {
  try {
    const props = PropertiesService.getScriptProperties();
    return props.getProperty('RGU_RCA_ATTIVO' + CURRENT_ENV.SUFFIX) !== 'FALSE';
  } catch (e) {
    return false;
  }
}

function toggleRguRcaModulo(token, newState) {
  try {
    const userCtx = verifySessionAndGetUser(token);
    if (String(userCtx.ruolo).toUpperCase() !== 'ADMIN' && String(userCtx.ruolo).toUpperCase() !== 'MINISTERO') {
      throw new Error("Non autorizzato ad eseguire questa operazione.");
    }
    const props = PropertiesService.getScriptProperties();
    props.setProperty('RGU_RCA_ATTIVO' + CURRENT_ENV.SUFFIX, newState ? 'TRUE' : 'FALSE');
    return { success: true, message: newState ? "Modulo RGU/RCA ATTIVATO globalmente." : "Modulo RGU/RCA DISATTIVATO globalmente." };
  } catch (e) {
    return { success: false, message: e.message };
  }
}

function fetchInstitutionDetailForMinistero(token, idIstituzione) {
  try {
    const userCtx = verifySessionAndGetUser(token);
    const ruolo = String(userCtx.ruolo).toUpperCase();
    if (ruolo !== 'ADMIN' && ruolo !== 'MINISTERO') {
      throw new Error("Accesso negato: Funzione riservata esclusivamente agli amministratori ministeriali.");
    }
    
    const idIst = String(idIstituzione).trim();
    const ssDb = SpreadsheetApp.openById(DB_CONFIG.ID_RGU_RCA);
    const sheetTrans = ssDb.getSheetByName(DB_CONFIG.SHEET_RGU_RCA_TRANS);
    const transData = sheetTrans ? sheetTrans.getDataRange().getValues() : [];

    const activeNominations = {};
    const storicoList = [];

    // Pattern Event Sourcing per Ricostruzione Stato Istituzione Selezionata
    for (let i = 1; i < transData.length; i++) {
      if (String(transData[i][1]).trim() !== idIst) continue;
      const idTrans = transData[i][0];
      const stato = transData[i][3];
      const payload = JSON.parse(transData[i][4]);
      payload.ruoloControllato = transData[i][2];

      if (stato === "ATTIVO") {
        payload.idTransazione = idTrans;
        activeNominations[idTrans] = payload;
      } else if (stato === "CESSATO") {
        const originalId = payload.idTransNominaOriginale;
        if (activeNominations[originalId]) {
          const storicized = Object.assign({}, activeNominations[originalId]);
          storicized.dataCessazione = payload.dataCessazione;
          storicized.motivoCessazione = payload.motivoCessazione || "N/A";
          storicoList.push(storicized);
          delete activeNominations[originalId];
        }
      }
    }

    storicoList.sort((a, b) => new Date(b.dataCessazione) - new Date(a.dataCessazione));
    return { 
      success: true, 
      attivi: Object.values(activeNominations), 
      storico: storicoList, 
      denom: getInstitutionNameById(idIst) 
    };
  } catch (e) {
    return { success: false, message: e.message };
  }
}

function syncRguRcaExport_() {
  const lock = LockService.getScriptLock();
  try {
    if (!lock.tryLock(10000)) return;
  } catch (e) { return; }

  try {
    const properties = PropertiesService.getScriptProperties();
    let lastSyncedRow = parseInt(properties.getProperty('RGU_RCA_LAST_SYNCED_ROW') || '1', 10);
    const ss = SpreadsheetApp.openById(DB_CONFIG.ID_RGU_RCA); // Fix: DB specifico per RGU_RCA
    const sheetTrans = ss.getSheetByName(DB_CONFIG.SHEET_RGU_RCA_TRANS);
    const sheetExport = ss.getSheetByName(DB_CONFIG.SHEET_RGU_RCA_EXP);
    const ssMaster = SpreadsheetApp.openById(DB_CONFIG.MASTER_ID);
    const sheetIst = ssMaster.getSheetByName(DB_CONFIG.SHEET_ISTITUZIONI);

    if (!sheetTrans || !sheetExport || !sheetIst) throw new Error("Dato mancante, necessaria verifica fogli di sincronizzazione.");

    const lastRowTrans = sheetTrans.getLastRow();
    if (lastRowTrans <= lastSyncedRow) return;

    const dataIst = sheetIst.getDataRange().getValues();
    const mapIstituzioni = {};
    for (let k = 1; k < dataIst.length; k++) mapIstituzioni[String(dataIst[k][0]).trim()] = dataIst[k][1];

    const numRowsToSync = lastRowTrans - lastSyncedRow;
    const newTransData = sheetTrans.getRange(lastSyncedRow + 1, 1, numRowsToSync, 7).getValues();
    const lastRowExport = Math.max(sheetExport.getLastRow(), 1);
    
    let mapExportIndices = {};
    if (lastRowExport > 1) {
      const exportIds = sheetExport.getRange(2, 1, lastRowExport - 1, 1).getValues();
      for (let x = 0; x < exportIds.length; x++) {
        mapExportIndices[String(exportIds[x][0]).trim()] = x + 2;
      }
    }

    const timestampSync = new Date();
    const rowsToAppend = [];

    for (let i = 0; i < newTransData.length; i++) {
      const idTrans = String(newTransData[i][0]).trim();
      const idIst = String(newTransData[i][1]).trim();
      const ruolo = String(newTransData[i][2]).trim();
      const stato = String(newTransData[i][3]).trim();
      const rawJson = newTransData[i][4];
      const operatore = String(newTransData[i][5] || "").trim();
      if (!rawJson) continue;

      try {
        const payload = JSON.parse(rawJson);
        if (stato === "ATTIVO") {
          const flagCda = payload.flagIncaricoCdaAdInterim ? "SI" : "NO";
          const dataInizio = payload.dataAttivazione ? new Date(payload.dataAttivazione) : "";
          const denom = mapIstituzioni[idIst] || "Dato mancante, necessaria verifica";
          
          rowsToAppend.push([
            idTrans, idIst, denom, ruolo, payload.cognome, payload.nome, payload.codiceFiscale, 
            payload.profiloSelezionato, flagCda, payload.qualificaDirettivaDocente || "", 
            payload.notaGiustificativaDocente || "", dataInizio, "", "SI", operatore, timestampSync
          ]);
        } else if (stato === "CESSATO") {
          const originalId = String(payload.idTransNominaOriginale || "").trim();
          const targetRowIndex = mapExportIndices[originalId];
          if (targetRowIndex) {
            const dataCess = payload.dataCessazione ? new Date(payload.dataCessazione) : new Date();
            sheetExport.getRange(targetRowIndex, 13, 1, 4).setValues([[dataCess, "NO", operatore, timestampSync]]);
          }
        }
      } catch (err) { }
    }

    if (rowsToAppend.length > 0) {
      sheetExport.getRange(sheetExport.getLastRow() + 1, 1, rowsToAppend.length, rowsToAppend[0].length).setValues(rowsToAppend);
    }
    properties.setProperty('RGU_RCA_LAST_SYNCED_ROW', String(lastRowTrans));
    SpreadsheetApp.flush();
  } catch (e) {
  } finally {
    lock.releaseLock();
  }
}