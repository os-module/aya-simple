use thiserror_no_std::Error;
#[derive(Debug, Error)]
#[repr(i32)]
pub enum KError {
    #[error("Invalid argument")]
    KInvalid = 0,
    #[error("No such file or directory")]
    KENOENT = 2,
}
