#!/usr/bin/env bash
set -euo pipefail

repo_root=$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &&
        pwd
)

cd "$repo_root"

package_name=${PACKAGE_NAME:-$(awk -F '"' '/^name = / { print $2; exit }' Cargo.toml)}
package_version=${PACKAGE_VERSION:-$(awk -F '"' '/^version = / { print $2; exit }' Cargo.toml)}
package_arch=${PACKAGE_ARCH:-$(dpkg-architecture -qDEB_HOST_ARCH)}

output_dir=${OUTPUT_DIR:-"$repo_root/target/debian"}
build_root="$output_dir/.build/${package_name}_${package_version}_${package_arch}"
staging_dir="$build_root/root"
binary_path="$repo_root/target/release/$package_name"
deb_path="$output_dir/${package_name}_${package_version}_${package_arch}.deb"

maintainer_name=${DEBFULLNAME:-$(git config --get user.name 2>/dev/null || id -un)}
maintainer_email=$(
    if [[ -n ${DEBEMAIL:-} ]]; then
        printf '%s\n' "$DEBEMAIL"
    elif git config --get user.email >/dev/null 2>&1; then
        git config --get user.email
    else
        printf '%s@%s\n' "$(id -un)" "$(hostname -f 2>/dev/null || hostname)"
    fi
)

require_tool() {
    local tool=$1
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 1
    fi
}

for tool in awk cargo dpkg-architecture dpkg-deb install; do
    require_tool "$tool"
done

mkdir -p "$output_dir"
rm -rf "$build_root"

cargo build --release --locked

if [[ ! -x "$binary_path" ]]; then
    printf 'expected release binary at %s\n' "$binary_path" >&2
    exit 1
fi

install -d \
    "$staging_dir/DEBIAN" \
    "$staging_dir/usr/bin" \
    "$staging_dir/usr/lib/narrowd" \
    "$staging_dir/usr/lib/systemd/user" \
    "$staging_dir/usr/share/doc/$package_name/examples"

install -Dm755 "$binary_path" "$staging_dir/usr/bin/$package_name"
install -Dm755 "$repo_root/packaging/narrowd-user-service" \
    "$staging_dir/usr/lib/narrowd/narrowd-user-service"
install -Dm644 "$repo_root/packaging/systemd-user/narrowd.service" \
    "$staging_dir/usr/lib/systemd/user/narrowd.service"
install -Dm644 "$repo_root/narrowd.conf.example" \
    "$staging_dir/usr/share/doc/$package_name/examples/narrowd.conf.example"
install -Dm644 "$repo_root/README.md" \
    "$staging_dir/usr/share/doc/$package_name/README.md"

depends_line=
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
    shlibs_log="$build_root/dpkg-shlibdeps.log"
    install -d "$build_root/debian"
    {
        printf 'Source: %s\n' "$package_name"
        printf 'Section: net\n'
        printf 'Priority: optional\n'
        printf 'Maintainer: %s <%s>\n' "$maintainer_name" "$maintainer_email"
        printf 'Standards-Version: 4.7.0\n'
        printf '\n'
        printf 'Package: %s\n' "$package_name"
        printf 'Architecture: any\n'
        printf 'Description: temporary metadata for dpkg-shlibdeps\n'
    } >"$build_root/debian/control"

    if shlibs_output=$(
        cd "$build_root" &&
            dpkg-shlibdeps -O -Tdebian/substvars "$staging_dir/usr/bin/$package_name" \
                2>"$shlibs_log"
    ); then
        if [[ -s "$shlibs_log" ]]; then
            cat "$shlibs_log" >&2
        fi
        shlibs_deps=${shlibs_output#shlibs:Depends=}
        if [[ -n "$shlibs_deps" && "$shlibs_deps" != "$shlibs_output" ]]; then
            depends_line="Depends: $shlibs_deps"
        fi
    else
        if [[ -s "$shlibs_log" ]]; then
            printf 'warning: unable to calculate shared-library dependencies:\n' >&2
            cat "$shlibs_log" >&2
        else
            printf 'warning: unable to calculate shared-library dependencies\n' >&2
        fi
    fi
fi

{
    printf 'Package: %s\n' "$package_name"
    printf 'Version: %s\n' "$package_version"
    printf 'Section: net\n'
    printf 'Priority: optional\n'
    printf 'Architecture: %s\n' "$package_arch"
    printf 'Maintainer: %s <%s>\n' "$maintainer_name" "$maintainer_email"
    if [[ -n "$depends_line" ]]; then
        printf '%s\n' "$depends_line"
    fi
    printf 'Description: single-user Rust SSH daemon\n'
    printf ' Packaged for local installation with a non-root systemd user service.\n'
    printf ' The package installs the narrowd binary, a user unit, and an example\n'
    printf ' config that can be copied into ~/.config/narrowd/.\n'
} >"$staging_dir/DEBIAN/control"

dpkg-deb --build --root-owner-group "$staging_dir" "$deb_path" >/dev/null

printf 'Built Debian package: %s\n' "$deb_path"
printf '\n'
printf 'Install and start it for your user account:\n'
printf '  sudo apt install ./%s\n' "${deb_path#$repo_root/}"
printf '  mkdir -p ~/.config/narrowd\n'
printf '  cp /usr/share/doc/%s/examples/narrowd.conf.example ~/.config/narrowd/narrowd.conf\n' \
    "$package_name"
printf '  sudo loginctl enable-linger "$USER"\n'
printf '  systemctl --user enable --now narrowd.service\n'
