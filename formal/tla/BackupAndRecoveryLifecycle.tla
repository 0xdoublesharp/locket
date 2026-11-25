---------------------- MODULE BackupAndRecoveryLifecycle -----------------------
EXTENDS Integers

CONSTANTS NoValue, OldCode, NewCode, Master, Signing, Sealing, PriorMaster, PriorSealing

VARIABLES export, import, config, rotate, restore, vault, audit
vars == <<export, import, config, rotate, restore, vault, audit>>

Operations == {"BACKUP_EXPORT", "BACKUP_IMPORT", "CONFIG_UPDATE", "RECOVERY_ROTATE",
               "RECOVERY_RESTORE_BEGIN", "RECOVER"}
Terminal == {"failed", "done", "interrupted"}
Kinds == {"master", "signing", "sealing"}
Keys == [master |-> Master, signing |-> Signing, sealing |-> Sealing]
PriorKeys == [master |-> PriorMaster, signing |-> NoValue, sealing |-> PriorSealing]

(* Cryptography is symbolic. Each entry authenticates its kind and is bound
   to the recovery code. Rotation changes the wrapping code, keeping the
   master key and both independent device keys. *)
Seal(code, keys) == [kind \in Kinds |-> <<code, kind, keys[kind]>>]
Unwrap(envelope, code, kind) ==
    IF envelope[kind][1] = code /\ envelope[kind][2] = kind
    THEN envelope[kind][3] ELSE NoValue

OriginalEnvelope == Seal(OldCode, Keys)
RotatedEnvelope == Seal(NewCode, Keys)
BundleDigest == "sealed-bundle-digest"

Profile(occupancy) ==
    [nameOwner |-> "local", local |-> occupancy, archive |-> NoValue,
     importedDangerous |-> FALSE, value |-> "local", policy |-> {"read"}]
ImportRequest == [signature : {"verified", "unsigned"}, dangerous : BOOLEAN,
                  confirm : BOOLEAN, mode : {"review", "incoming", "local"},
                  proposedPolicy : {{"read", "deploy"}}]
IdleImport == [phase |-> "idle", request |-> NoValue, draft |-> NoValue]
ImportState(phase, request, draft) ==
    [phase |-> phase, request |-> request, draft |-> draft]

Init ==
    /\ export = "idle"
    /\ import = IdleImport
    /\ config = "idle"
    /\ rotate = "idle"
    /\ restore = "idle"
    /\ \E occupancy \in {"empty", "populated"} :
         vault = [bundle |-> NoValue, profile |-> Profile(occupancy),
                  settings |-> "old", dangerous |-> FALSE,
                  recovery |-> OriginalEnvelope, liveKeys |-> PriorKeys]
    /\ audit = [op \in Operations |-> NoValue]

(* Seal before audit. Only the audited digest can reach the public path.
   A crash can discard either a sealed draft or an audited, unpublished
   export. The latter may leave an audit row without a public bundle. *)
SealExport ==
    /\ export = "idle" /\ export' = "sealed"
    /\ UNCHANGED <<import, config, rotate, restore, vault, audit>>

AuditExport ==
    /\ export = "sealed" /\ export' = "audited"
    /\ audit' = [audit EXCEPT !["BACKUP_EXPORT"] = BundleDigest]
    /\ UNCHANGED <<import, config, rotate, restore, vault>>

PublishExport ==
    /\ export = "audited" /\ export' = "done"
    /\ vault' = [vault EXCEPT !.bundle = BundleDigest]
    /\ UNCHANGED <<import, config, rotate, restore, audit>>

AbortExport ==
    /\ export \in {"sealed", "audited"} /\ export' = "failed"
    /\ UNCHANGED <<import, config, rotate, restore, vault, audit>>

StartImport(request) ==
    /\ import.phase = "idle"
    /\ import' = ImportState("verified", request, NoValue)
    /\ UNCHANGED <<export, config, rotate, restore, vault, audit>>

Confirmed(request) == request.confirm \/ ~(request.dangerous \/ vault.dangerous)

(* Both identities contribute proposed command metadata. The sealed-bundle
   handlers leave approval to the local policy operation. A populated
   same-name profile has an incompatible identity even for a signed bundle. *)
StageImport ==
    /\ import.phase = "verified"
    /\ Confirmed(import.request)
    /\ vault.profile.local = "empty"
    /\ LET draft == [vault.profile EXCEPT !.nameOwner = "incoming", !.archive = "local",
                      !.importedDangerous = import.request.dangerous]
       IN import' = ImportState("archived", import.request, draft)
    /\ UNCHANGED <<export, config, rotate, restore, vault, audit>>

StageConflict ==
    /\ import.phase = "archived"
    /\ import' = ImportState("staged", import.request,
                             [import.draft EXCEPT !.value =
                                 IF import.request.mode = "incoming" THEN "incoming" ELSE "local"])
    /\ UNCHANGED <<export, config, rotate, restore, vault, audit>>

CommitImport ==
    /\ import.phase = "staged"
    /\ import.request.mode # "review"
    /\ Confirmed(import.request)
    /\ audit' = [audit EXCEPT !["BACKUP_IMPORT"] =
          [request |-> import.request, before |-> vault.profile, after |-> import.draft,
           localDangerous |-> vault.dangerous]]
    /\ vault' = [vault EXCEPT !.profile = import.draft]
    /\ import' = ImportState("done", NoValue, NoValue)
    /\ UNCHANGED <<export, config, rotate, restore>>

AbortImport ==
    /\ import.phase \in {"verified", "archived", "staged"}
    /\ import' = ImportState("failed", NoValue, NoValue)
    /\ UNCHANGED <<export, config, rotate, restore, vault, audit>>

(* Validation and audit failures can discard either part of the staged
   update. Config represents settled settings after the daemon has either
   completed the write or compensated for a reported filesystem or SQL error. *)
StageSettings ==
    /\ config = "idle" /\ config' = "settings"
    /\ UNCHANGED <<export, import, rotate, restore, vault, audit>>

StageProfile ==
    /\ config = "settings" /\ config' = "profile"
    /\ UNCHANGED <<export, import, rotate, restore, vault, audit>>

CommitConfig ==
    /\ config = "profile" /\ config' = "done"
    /\ vault' = [vault EXCEPT !.settings = "new", !.dangerous = TRUE]
    /\ audit' = [audit EXCEPT !["CONFIG_UPDATE"] = <<"new", TRUE>>]
    /\ UNCHANGED <<export, import, rotate, restore>>

AbortConfig ==
    /\ config \in {"settings", "profile"} /\ config' = "failed"
    /\ UNCHANGED <<export, import, rotate, restore, vault, audit>>

StageRotation ==
    /\ rotate = "idle" /\ rotate' = "rewrapped"
    /\ UNCHANGED <<export, import, config, restore, vault, audit>>

AuditRotation ==
    /\ rotate = "rewrapped" /\ rotate' = "audited"
    /\ audit' = [audit EXCEPT !["RECOVERY_ROTATE"] = RotatedEnvelope]
    /\ UNCHANGED <<export, import, config, restore, vault>>

PublishRotation ==
    /\ rotate = "audited" /\ rotate' = "done"
    /\ vault' = [vault EXCEPT !.recovery = RotatedEnvelope]
    /\ UNCHANGED <<export, import, config, restore, audit>>

AbortRotation ==
    /\ rotate \in {"rewrapped", "audited"} /\ rotate' = "failed"
    /\ UNCHANGED <<export, import, config, restore, vault, audit>>

(* The intent survives interrupted compensation. Failed writes that return
   to the caller compensate in reverse order and keep the prior keys. The
   intent binds the keychain and device writes to the authenticated envelope. *)
AuditRestore ==
    /\ restore = "idle" /\ restore' = "audited"
    /\ audit' = [audit EXCEPT !["RECOVERY_RESTORE_BEGIN"] = vault.recovery]
    /\ UNCHANGED <<export, import, config, rotate, vault>>

WriteRestoreMaster ==
    /\ restore = "audited" /\ restore' = "master"
    /\ vault' = [vault EXCEPT !.liveKeys.master = Master]
    /\ UNCHANGED <<export, import, config, rotate, audit>>

WriteRestoreSealing ==
    /\ restore = "master" /\ restore' = "sealing"
    /\ vault' = [vault EXCEPT !.liveKeys.sealing = Sealing]
    /\ UNCHANGED <<export, import, config, rotate, audit>>

WriteRestoreSigning ==
    /\ restore = "sealing" /\ restore' = "signing"
    /\ vault' = [vault EXCEPT !.liveKeys.signing = Signing]
    /\ UNCHANGED <<export, import, config, rotate, audit>>

CommitRestore ==
    /\ restore = "signing" /\ restore' = "done"
    /\ audit' = [audit EXCEPT !["RECOVER"] = Keys]
    /\ UNCHANGED <<export, import, config, rotate, vault>>

AbortRestore ==
    /\ restore \in {"idle", "audited"} \cup Kinds /\ restore' = "failed"
    /\ vault' = [vault EXCEPT !.liveKeys = PriorKeys]
    /\ UNCHANGED <<export, import, config, rotate, audit>>

InterruptRestore ==
    /\ restore \in Kinds /\ restore' = "interrupted"
    /\ UNCHANGED <<export, import, config, rotate, vault, audit>>

Quiescent ==
    /\ {export, import.phase, config, rotate, restore} \subseteq Terminal
    /\ UNCHANGED vars

Next ==
    \/ SealExport \/ AuditExport \/ PublishExport \/ AbortExport
    \/ (\E request \in ImportRequest : StartImport(request))
    \/ StageImport \/ StageConflict \/ CommitImport \/ AbortImport
    \/ StageSettings \/ StageProfile \/ CommitConfig \/ AbortConfig
    \/ StageRotation \/ AuditRotation \/ PublishRotation \/ AbortRotation
    \/ AuditRestore \/ WriteRestoreMaster \/ WriteRestoreSealing \/ WriteRestoreSigning
    \/ CommitRestore \/ AbortRestore \/ InterruptRestore \/ Quiescent

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ export \in {"idle", "sealed", "audited"} \cup Terminal
    /\ import.phase \in {"idle", "verified", "archived", "staged"} \cup Terminal
    /\ config \in {"idle", "settings", "profile"} \cup Terminal
    /\ rotate \in {"idle", "rewrapped", "audited"} \cup Terminal
    /\ restore \in {"idle", "audited"} \cup Kinds \cup Terminal
    /\ DOMAIN audit = Operations
    /\ vault.bundle \in {NoValue, BundleDigest}
    /\ vault.settings \in {"old", "new"}
    /\ vault.dangerous \in BOOLEAN
    /\ vault.recovery \in {OriginalEnvelope, RotatedEnvelope}
    /\ DOMAIN vault.liveKeys = Kinds
    /\ \A kind \in Kinds : vault.liveKeys[kind] \in {PriorKeys[kind], Keys[kind]}

NoUnauditedMutation ==
    /\ vault.bundle # NoValue => audit["BACKUP_EXPORT"] = vault.bundle
    /\ IF audit["BACKUP_IMPORT"] = NoValue
       THEN vault.profile \in {Profile("empty"), Profile("populated")}
       ELSE audit["BACKUP_IMPORT"].after = vault.profile
    /\ IF vault.settings = "new" \/ vault.dangerous
       THEN audit["CONFIG_UPDATE"] = <<vault.settings, vault.dangerous>>
       ELSE audit["CONFIG_UPDATE"] = NoValue
    /\ vault.recovery # OriginalEnvelope => audit["RECOVERY_ROTATE"] = vault.recovery
    /\ LET intent == audit["RECOVERY_RESTORE_BEGIN"]
       IN vault.liveKeys # PriorKeys =>
          /\ intent \in {OriginalEnvelope, RotatedEnvelope}
          /\ \A kind \in Kinds : vault.liveKeys[kind] # PriorKeys[kind] =>
                Unwrap(intent, intent[kind][1], kind) = vault.liveKeys[kind]
    /\ restore = "done" => audit["RECOVER"] = vault.liveKeys /\ vault.liveKeys = Keys

NoUnsignedPrivilegeEscalation ==
    LET row == audit["BACKUP_IMPORT"]
    IN row # NoValue =>
       /\ row.request.dangerous \/ row.localDangerous => row.request.confirm
       /\ row.request.signature = "unsigned" =>
           /\ row.after.policy \subseteq row.before.policy
           /\ row.before.local = "populated" => row.after = row.before

ImportArchiveAndConflictIntegrity ==
    LET row == audit["BACKUP_IMPORT"]
    IN row # NoValue =>
       /\ row.before.local = "empty" /\ row.after.local = row.before.local
       /\ row.after.archive = row.before.nameOwner /\ row.after.nameOwner = "incoming"
       /\ row.request.mode \in {"incoming", "local"}
       /\ row.after.value = row.request.mode

ConfigPartsAgree ==
    /\ (vault.settings = "new") = vault.dangerous
    /\ config = "failed" => audit["CONFIG_UPDATE"] = NoValue

RecoveryKeyContinuity ==
    /\ rotate = "failed" => vault.recovery = OriginalEnvelope
    /\ \A kind \in Kinds :
         Unwrap(vault.recovery, IF rotate = "done" THEN NewCode ELSE OldCode, kind) = Keys[kind]
    /\ restore = "failed" => vault.liveKeys = PriorKeys /\ audit["RECOVER"] = NoValue

=============================================================================
