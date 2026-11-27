use std::fs::{DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

pub fn prepare(settings: &mut Permissions, directory: &mut DirBuilder) {
    settings.set_readonly(false);
    directory.mode(755);
}

pub fn restrict(settings: &mut Permissions, directory: &mut DirBuilder) {
    settings.set_readonly(true);
    settings.set_mode(0o640);
    directory.mode(0o750);
}
