//! Windows file identity without reading bytes through a separately locked handle.
//!
//! SAFETY-AUDIT: the borrowed File keeps its handle alive during the metadata
//! query. Windows initializes a correctly sized, aligned `FILE_ID_INFO` output.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
};

pub(super) fn same_file(left: &File, right: &File) -> io::Result<bool> {
    Ok(identity(left)? == identity(right)?)
}

fn identity(file: &File) -> io::Result<(u64, [u8; 16])> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: File owns this live handle, and the API writes exactly the
    // requested structure. Metadata queries do not read locked byte ranges.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut information).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).map_err(io::Error::other)?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((information.VolumeSerialNumber, information.FileId.Identifier))
}
