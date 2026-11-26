//! `locket emit-example` command.

use std::io::Write;

use locket_crypto::KeyPurpose;

use crate::{
    CliError, RuntimeContext, collect_example_secret_names, load_project_key, open_store,
    require_project, write_example_block_for_emit, write_example_emit_audit,
};

pub fn emit_example_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    replace: bool,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let names = collect_example_secret_names(&store, &resolved)?;
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let result = write_example_block_for_emit(context, &resolved.root, &names, replace, output)?;
    write_example_emit_audit(&mut store, &resolved, audit_key.as_ref(), &result)?;
    writeln!(output, "updated {}", result.path.display())?;
    Ok(())
}
