---- MODULE McpAndDesktopBoundary ----
CONSTANT VerifiedOpen

Inspect == "locket_inspect_env_keys"
Scan == "locket_scan_env_files"
Import == "locket_import_env"
Detect == "locket_detect_commands"
DesktopMetadata == "desktop_metadata"
DesktopOverwrite == "desktop_crud_overwrite"
FileTools == {Inspect, Scan, Import, Detect}
Tools == FileTools \cup {DesktopMetadata, DesktopOverwrite}
RealNames == {"secret-name", "project-id", "profile-id"}
Alias(name) ==
    CASE name = "secret-name" -> "secret-alias"
      [] name = "project-id" -> "project-alias"
      [] name = "profile-id" -> "profile-alias"
Aliases == {Alias(name) : name \in RealNames}
Plaintext == "plaintext-secret"
Missing == "none"

Request(tool, root, privacy, confirm, dryRun, overwrite) ==
    [tool |-> tool, root |-> root, privacy_mode |-> privacy,
     confirm_dangerous |-> confirm, dry_run |-> dryRun, overwrite |-> overwrite]
NoRequest == Request(Missing, Missing, FALSE, FALSE, FALSE, FALSE)
NoCommit == [wrote |-> FALSE, dangerous |-> FALSE, overwrite |-> FALSE, confirmed |-> FALSE]
RawMetadata == RealNames \cup {Plaintext}

VARIABLES request, fs, phase, handle, readFrom, loaded, response, commit
vars == <<request, fs, phase, handle, readFrom, loaded, response, commit>>

Init ==
    /\ request = NoRequest
    /\ fs = [parentLink |-> FALSE, fileLink |-> FALSE, regular |-> TRUE, dangerous |-> FALSE]
    /\ phase = "idle"
    /\ handle = Missing
    /\ readFrom = Missing
    /\ loaded = {}
    /\ response = {}
    /\ commit = NoCommit

Begin ==
    /\ phase = "idle"
    /\ \E tool \in Tools, root \in {"cwd", "trusted-project", "outside"},
          privacy, confirm, dryRun, overwrite \in BOOLEAN:
        /\ tool \notin FileTools => root = "cwd"
        /\ tool # Import => ~dryRun
        /\ tool \notin {Import, DesktopOverwrite} => ~confirm
        /\ tool # Import => overwrite = (tool = DesktopOverwrite)
        /\ request' = Request(tool, root, privacy, confirm, dryRun, overwrite)
        /\ phase' = IF tool \in FileTools THEN "resolve" ELSE "respond"
        /\ loaded' = IF tool \in FileTools THEN {} ELSE RawMetadata
    /\ UNCHANGED <<fs, handle, readFrom, response, commit>>

\* The actor can substitute either path component before or after validation/open.
FilesystemChange ==
    /\ phase \notin {"idle", "done"}
    /\ fs' \in [parentLink : BOOLEAN, fileLink : BOOLEAN, regular : BOOLEAN, dangerous : BOOLEAN]
    /\ UNCHANGED <<request, phase, handle, readFrom, loaded, response, commit>>

Resolve ==
    /\ phase = "resolve"
    /\ phase' = IF request.root = "outside" \/ fs.parentLink \/ fs.fileLink \/ ~fs.regular
                THEN "done" ELSE "validated"
    /\ UNCHANGED <<request, fs, handle, readFrom, loaded, response, commit>>

\* The lookup consumes the current filesystem, which may differ from the validated one.
PathBasedTarget ==
    IF fs.parentLink \/ fs.fileLink THEN "outside"
    ELSE IF fs.regular THEN request.root ELSE Missing

\* Directory-relative no-follow opening and a regular-file check on the descriptor.
VerifiedTarget ==
    IF fs.parentLink \/ fs.fileLink \/ ~fs.regular THEN Missing ELSE request.root

Open ==
    /\ phase = "validated"
    /\ handle' = IF VerifiedOpen THEN VerifiedTarget ELSE PathBasedTarget
    /\ phase' = IF handle' = Missing THEN "done" ELSE "opened"
    /\ UNCHANGED <<request, fs, readFrom, loaded, response, commit>>

\* Reads use the same opened object even when the path changes again.
Read ==
    /\ phase = "opened"
    /\ readFrom' = handle
    /\ loaded' = RawMetadata
    /\ phase' = "respond"
    /\ UNCHANGED <<request, fs, handle, response, commit>>

Respond ==
    /\ phase = "respond"
    /\ LET write == request.tool \in {Import, DesktopOverwrite} /\ ~request.dry_run
           allowed == ~request.overwrite \/ ~fs.dangerous \/ request.confirm_dangerous
           names == loaded \cap RealNames
       IN /\ commit' = IF write /\ allowed
                       THEN [wrote |-> TRUE, dangerous |-> fs.dangerous,
                             overwrite |-> request.overwrite, confirmed |-> request.confirm_dangerous]
                       ELSE NoCommit
          /\ response' = IF write /\ ~allowed THEN {}
                         ELSE IF request.privacy_mode THEN {Alias(name) : name \in names}
                         ELSE names
    /\ phase' = "done"
    /\ UNCHANGED <<request, fs, handle, readFrom, loaded>>

Next == Begin \/ FilesystemChange \/ Resolve \/ Open \/ Read \/ Respond
Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ phase \in {"idle", "resolve", "validated", "opened", "respond", "done"}
    /\ request = NoRequest \/ request \in [tool : Tools, root : {"cwd", "trusted-project", "outside"},
        privacy_mode : BOOLEAN, confirm_dangerous : BOOLEAN, dry_run : BOOLEAN, overwrite : BOOLEAN]
    /\ fs \in [parentLink : BOOLEAN, fileLink : BOOLEAN, regular : BOOLEAN, dangerous : BOOLEAN]
    /\ handle \in {Missing, "cwd", "trusted-project", "outside"}
    /\ readFrom \in {Missing, "cwd", "trusted-project", "outside"}
    /\ loaded \subseteq RawMetadata
    /\ response \subseteq RawMetadata \cup Aliases
    /\ commit \in [wrote : BOOLEAN, dangerous : BOOLEAN, overwrite : BOOLEAN, confirmed : BOOLEAN]

NoSecretValueCrossesBoundary == Plaintext \notin response

NoOutOfRootRead ==
    readFrom # Missing => /\ readFrom = request.root
                           /\ readFrom \in {"cwd", "trusted-project"}

DangerousOverwriteRequiresConfirmation ==
    commit.wrote => /\ ~request.dry_run
                    /\ (commit.dangerous /\ commit.overwrite) => commit.confirmed

PrivacyModeHidesRealNames ==
    request.privacy_mode => response \cap RealNames = {}
====
