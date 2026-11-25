//! Execution commands: exec, run, env, compose.

pub mod compose;
pub mod docker;
mod docker_context;
pub mod env;
#[allow(clippy::module_inception)]
pub mod exec;
pub mod run;

fn prepare_vault_execution(
    request: &locket_exec::ExecutionRequest,
) -> Result<locket_exec::PreparedExecution, crate::CliError> {
    for name in request.locket_env.keys() {
        ensure_vault_env_name(name)?;
    }
    locket_exec::prepare_execution(request).map_err(crate::runtime::error::exec_prepare_error)
}

fn ensure_vault_env_name(name: &str) -> Result<(), crate::CliError> {
    if locket_exec::is_child_runtime_control(name) {
        return Err(crate::runtime::error::invalid_policy_error(format!(
            "vault secret cannot set a child startup variable: {name}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use locket_exec::{ExecutionRequest, env_value};

    #[test]
    fn vault_values_cannot_set_child_startup_controls() {
        for name in [
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "BASH_ENV",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PATH",
        ] {
            let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
            request.locket_env.insert(name.to_owned(), env_value("synthetic-startup-value"));

            let result = super::prepare_vault_execution(&request);
            assert!(matches!(
                result,
                Err(crate::CliError::Typed { kind: locket_core::LocketError::InvalidPolicy, .. })
            ));
        }
    }
}
