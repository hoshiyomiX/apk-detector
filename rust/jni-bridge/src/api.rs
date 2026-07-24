//! JNI exports consumed by the Kotlin app `id.zai.apkdetector`.
//!
//! We hand-roll the minimal FFI layer instead of pulling in `jni-sys` or `jni`.
//! Only three JNIEnv functions are needed:
//!   - `GetStringUTFChars`   (read a Java String → *const c_char)
//!   - `ReleaseStringUTFChars` (free it)
//!   - `NewStringUTF`         (create a Java String from *const c_char)
//!
//! All exported native methods are `extern "system"` (JNICALL on ARM/x86).

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::OnceLock;

use detector::{full_scan, ReportDiff};
use signatures::SignatureSet as SigSet;

use crate::ensure_logger;

/// Cached `SignatureSet` — loading ~50 YAML rules is expensive enough to memoize.
static SIGS: OnceLock<Option<SigSet>> = OnceLock::new();

fn sigs() -> Result<&'static SigSet, String> {
    let opt = SIGS.get_or_init(|| SigSet::load_embedded().ok());
    opt.as_ref().ok_or_else(|| "embedded signature set failed to load".to_string())
}

// ---------------------------------------------------------------------------
// Minimal JNI FFI layer
// ---------------------------------------------------------------------------

/// Opaque JNIEnv handle. The JVM passes a `JNIEnv*` (i.e., `**const JNINativeInterface_`)
/// to native methods, but since we only need a fixed set of functions we model
/// the interface as a fixed-layout struct and index into it by offset.
///
/// The real `JNINativeInterface_` has ~230 function pointers. We declare only
/// the first ~170 leading up to `NewStringUTF` to keep the struct small while
/// giving the compiler a meaningful layout to deref.
///
/// Field offsets are stable ABI per the JNI spec.
#[repr(C)]
pub(crate) struct JNINativeInterface {
    _reserved0: *mut c_void,
    _reserved1: *mut c_void,
    _reserved2: *mut c_void,
    _reserved3: *mut c_void,
    _get_version: *mut c_void,
    _define_class: *mut c_void,
    _find_class: *mut c_void,
    _from_reflected_method: *mut c_void,
    _from_reflected_field: *mut c_void,
    _to_reflected_method: *mut c_void,
    _get_superclass: *mut c_void,
    _is_assignable_from: *mut c_void,
    _to_reflected_field: *mut c_void,
    _throw: *mut c_void,
    _throw_new: *mut c_void,
    _exception_occurred: *mut c_void,
    _exception_describe: *mut c_void,
    _exception_clear: *mut c_void,
    _fatal_error: *mut c_void,
    _push_local_frame: *mut c_void,
    _pop_local_frame: *mut c_void,
    _new_global_ref: *mut c_void,
    _delete_global_ref: *mut c_void,
    _delete_local_ref: *mut c_void,
    _is_same_object: *mut c_void,
    _new_local_ref: *mut c_void,
    _ensure_local_capacity: *mut c_void,
    _alloc_object: *mut c_void,
    _new_object: *mut c_void,
    _new_object_v: *mut c_void,
    _new_object_a: *mut c_void,
    _get_object_class: *mut c_void,
    _is_instance_of: *mut c_void,
    _get_method_id: *mut c_void,
    _call_object_method: *mut c_void,
    _call_object_method_v: *mut c_void,
    _call_object_method_a: *mut c_void,
    _call_boolean_method: *mut c_void,
    _call_boolean_method_v: *mut c_void,
    _call_boolean_method_a: *mut c_void,
    _call_byte_method: *mut c_void,
    _call_byte_method_v: *mut c_void,
    _call_byte_method_a: *mut c_void,
    _call_char_method: *mut c_void,
    _call_char_method_v: *mut c_void,
    _call_char_method_a: *mut c_void,
    _call_short_method: *mut c_void,
    _call_short_method_v: *mut c_void,
    _call_short_method_a: *mut c_void,
    _call_int_method: *mut c_void,
    _call_int_method_v: *mut c_void,
    _call_int_method_a: *mut c_void,
    _call_long_method: *mut c_void,
    _call_long_method_v: *mut c_void,
    _call_long_method_a: *mut c_void,
    _call_float_method: *mut c_void,
    _call_float_method_v: *mut c_void,
    _call_float_method_a: *mut c_void,
    _call_double_method: *mut c_void,
    _call_double_method_v: *mut c_void,
    _call_double_method_a: *mut c_void,
    _call_void_method: *mut c_void,
    _call_void_method_v: *mut c_void,
    _call_void_method_a: *mut c_void,
    _call_nonvirtual_object_method: *mut c_void,
    _call_nonvirtual_object_method_v: *mut c_void,
    _call_nonvirtual_object_method_a: *mut c_void,
    _call_nonvirtual_boolean_method: *mut c_void,
    _call_nonvirtual_boolean_method_v: *mut c_void,
    _call_nonvirtual_boolean_method_a: *mut c_void,
    _call_nonvirtual_byte_method: *mut c_void,
    _call_nonvirtual_byte_method_v: *mut c_void,
    _call_nonvirtual_byte_method_a: *mut c_void,
    _call_nonvirtual_char_method: *mut c_void,
    _call_nonvirtual_char_method_v: *mut c_void,
    _call_nonvirtual_char_method_a: *mut c_void,
    _call_nonvirtual_short_method: *mut c_void,
    _call_nonvirtual_short_method_v: *mut c_void,
    _call_nonvirtual_short_method_a: *mut c_void,
    _call_nonvirtual_int_method: *mut c_void,
    _call_nonvirtual_int_method_v: *mut c_void,
    _call_nonvirtual_int_method_a: *mut c_void,
    _call_nonvirtual_long_method: *mut c_void,
    _call_nonvirtual_long_method_v: *mut c_void,
    _call_nonvirtual_long_method_a: *mut c_void,
    _call_nonvirtual_float_method: *mut c_void,
    _call_nonvirtual_float_method_v: *mut c_void,
    _call_nonvirtual_float_method_a: *mut c_void,
    _call_nonvirtual_double_method: *mut c_void,
    _call_nonvirtual_double_method_v: *mut c_void,
    _call_nonvirtual_double_method_a: *mut c_void,
    _call_nonvirtual_void_method: *mut c_void,
    _call_nonvirtual_void_method_v: *mut c_void,
    _call_nonvirtual_void_method_a: *mut c_void,
    _get_field_id: *mut c_void,
    _get_object_field: *mut c_void,
    _get_boolean_field: *mut c_void,
    _get_byte_field: *mut c_void,
    _get_char_field: *mut c_void,
    _get_short_field: *mut c_void,
    _get_int_field: *mut c_void,
    _get_long_field: *mut c_void,
    _get_float_field: *mut c_void,
    _get_double_field: *mut c_void,
    _set_object_field: *mut c_void,
    _set_boolean_field: *mut c_void,
    _set_byte_field: *mut c_void,
    _set_char_field: *mut c_void,
    _set_short_field: *mut c_void,
    _set_int_field: *mut c_void,
    _set_long_field: *mut c_void,
    _set_float_field: *mut c_void,
    _set_double_field: *mut c_void,
    _get_static_method_id: *mut c_void,
    _call_static_object_method: *mut c_void,
    _call_static_object_method_v: *mut c_void,
    _call_static_object_method_a: *mut c_void,
    _call_static_boolean_method: *mut c_void,
    _call_static_boolean_method_v: *mut c_void,
    _call_static_boolean_method_a: *mut c_void,
    _call_static_byte_method: *mut c_void,
    _call_static_byte_method_v: *mut c_void,
    _call_static_byte_method_a: *mut c_void,
    _call_static_char_method: *mut c_void,
    _call_static_char_method_v: *mut c_void,
    _call_static_char_method_a: *mut c_void,
    _call_static_short_method: *mut c_void,
    _call_static_short_method_v: *mut c_void,
    _call_static_short_method_a: *mut c_void,
    _call_static_int_method: *mut c_void,
    _call_static_int_method_v: *mut c_void,
    _call_static_int_method_a: *mut c_void,
    _call_static_long_method: *mut c_void,
    _call_static_long_method_v: *mut c_void,
    _call_static_long_method_a: *mut c_void,
    _call_static_float_method: *mut c_void,
    _call_static_float_method_v: *mut c_void,
    _call_static_float_method_a: *mut c_void,
    _call_static_double_method: *mut c_void,
    _call_static_double_method_v: *mut c_void,
    _call_static_double_method_a: *mut c_void,
    _call_static_void_method: *mut c_void,
    _call_static_void_method_v: *mut c_void,
    _call_static_void_method_a: *mut c_void,
    _get_static_field_id: *mut c_void,
    _get_static_object_field: *mut c_void,
    _get_static_boolean_field: *mut c_void,
    _get_static_byte_field: *mut c_void,
    _get_static_char_field: *mut c_void,
    _get_static_short_field: *mut c_void,
    _get_static_int_field: *mut c_void,
    _get_static_long_field: *mut c_void,
    _get_static_float_field: *mut c_void,
    _get_static_double_field: *mut c_void,
    _set_static_object_field: *mut c_void,
    _set_static_boolean_field: *mut c_void,
    _set_static_byte_field: *mut c_void,
    _set_static_char_field: *mut c_void,
    _set_static_short_field: *mut c_void,
    _set_static_int_field: *mut c_void,
    _set_static_long_field: *mut c_void,
    _set_static_float_field: *mut c_void,
    _set_static_double_field: *mut c_void,
    _new_string: *mut c_void,
    _get_string_length: *mut c_void,
    _get_string_chars: *mut c_void,
    _release_string_chars: *mut c_void,
    _new_string_utf: NewStringUTFFn,
    _get_string_utf_length: *mut c_void,
    _get_string_utf_chars: GetStringUTFCharsFn,
    _release_string_utf_chars: ReleaseStringUTFCharsFn,
}

type NewStringUTFFn = unsafe extern "system" fn(env: *mut c_void, bytes: *const c_char) -> jstring;
type GetStringUTFCharsFn = unsafe extern "system" fn(
    env: *mut c_void,
    str_: jstring,
    is_copy: *mut u8,
) -> *const c_char;
type ReleaseStringUTFCharsFn = unsafe extern "system" fn(
    env: *mut c_void,
    str_: jstring,
    chars: *const c_char,
);

/// JNI opaque types (mirror of jni-sys's lowercase aliases).
#[allow(non_camel_case_types)]
pub(crate) type jobject = *mut c_void;
#[allow(non_camel_case_types)]
pub(crate) type jclass = jobject;
#[allow(non_camel_case_types)]
pub(crate) type jstring = jobject;
#[allow(non_camel_case_types)]
pub(crate) type jint = c_int;

/// The JVM passes `JNIEnv*` to native methods. `JNIEnv` is itself
/// `*const JNINativeInterface_`, so `JNIEnv*` is `**const ...`.
/// We accept it as `*mut *const JNINativeInterface` and double-deref.
pub(crate) type JNIEnvPtr = *mut *const JNINativeInterface;

unsafe fn iface(env: JNIEnvPtr) -> &'static JNINativeInterface {
    &**env
}

// ---------------------------------------------------------------------------
// JNI helpers
// ---------------------------------------------------------------------------

/// Convert a Java String to an owned Rust String.
unsafe fn jstr_to_string(env: JNIEnvPtr, jstr: jstring) -> Result<String, String> {
    if jstr.is_null() {
        return Err("null Java string".to_string());
    }
    let i = iface(env);
    let chars = (i._get_string_utf_chars)(env as *mut c_void, jstr, std::ptr::null_mut());
    if chars.is_null() {
        return Err("GetStringUTFChars returned null".to_string());
    }
    let cstr = CStr::from_ptr(chars);
    let s = cstr.to_str()
        .map(|s| s.to_owned())
        .map_err(|e| format!("utf8: {}", e));
    (i._release_string_utf_chars)(env as *mut c_void, jstr, chars);
    s
}

/// Return a Rust &str as a new Java String.
unsafe fn return_string(env: JNIEnvPtr, s: &str) -> jstring {
    let i = iface(env);
    let chars = s.as_bytes().as_ptr() as *const c_char;
    (i._new_string_utf)(env as *mut c_void, chars)
}

/// Wrap an error message as `{"error": "..."}` JSON for the Kotlin side to surface.
unsafe fn return_error(env: JNIEnvPtr, msg: &str) -> jstring {
    let json = format!("{{\"error\":\"{}\"}}", json_escape(msg));
    return_string(env, &json)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1) scanApk(path: String): String  — Markdown report (or {"error": "..."})
// ---------------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "system" fn Java_id_zai_apkdetector_NativeBridge_scanApk(
    env: JNIEnvPtr,
    _class: jclass,
    path_jstr: jstring,
) -> jstring {
    ensure_logger();
    log::info!("scanApk called");

    let path = match jstr_to_string(env, path_jstr) {
        Ok(s) => s,
        Err(e) => return return_error(env, &format!("path: {}", e)),
    };

    let sigs = match sigs() {
        Ok(s) => s,
        Err(e) => return return_error(env, &e),
    };

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => return return_error(env, &format!("open {}: {}", path, e)),
    };
    let mut apk = match apk_parser::Apk::open(file) {
        Ok(a) => a,
        Err(e) => return return_error(env, &format!("apk parse {}: {}", path, e)),
    };

    let report = full_scan(&path, &mut apk, sigs);
    let md = report.to_markdown(sigs);
    return_string(env, &md)
}

// ---------------------------------------------------------------------------
// 2) diffApks(oldPath: String, newPath: String): String  — Markdown diff
// ---------------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "system" fn Java_id_zai_apkdetector_NativeBridge_diffApks(
    env: JNIEnvPtr,
    _class: jclass,
    old_path_jstr: jstring,
    new_path_jstr: jstring,
) -> jstring {
    ensure_logger();
    log::info!("diffApks called");

    let old_path = match jstr_to_string(env, old_path_jstr) {
        Ok(s) => s,
        Err(e) => return return_error(env, &format!("oldPath: {}", e)),
    };
    let new_path = match jstr_to_string(env, new_path_jstr) {
        Ok(s) => s,
        Err(e) => return return_error(env, &format!("newPath: {}", e)),
    };

    let sigs = match sigs() {
        Ok(s) => s,
        Err(e) => return return_error(env, &e),
    };

    let old_report = match scan_to_findings(&old_path, sigs) {
        Ok(f) => f,
        Err(e) => return return_error(env, &format!("old APK: {}", e)),
    };
    let new_report = match scan_to_findings(&new_path, sigs) {
        Ok(f) => f,
        Err(e) => return return_error(env, &format!("new APK: {}", e)),
    };

    let diff = ReportDiff::from_findings(&old_report, &new_report);
    let md = diff.to_markdown(&old_path, &new_path);
    return_string(env, &md)
}

fn scan_to_findings(path: &str, sigs: &SigSet) -> Result<Vec<detector::Finding>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open {}: {}", path, e))?;
    let mut apk = apk_parser::Apk::open(file).map_err(|e| format!("apk parse {}: {}", path, e))?;
    let report = full_scan(path, &mut apk, sigs);
    Ok(report.findings)
}

// ---------------------------------------------------------------------------
// 3) listSignatures(): String  — JSON array of rule metadata
// ---------------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "system" fn Java_id_zai_apkdetector_NativeBridge_listSignatures(
    env: JNIEnvPtr,
    _class: jclass,
) -> jstring {
    ensure_logger();
    let sigs = match sigs() {
        Ok(s) => s,
        Err(e) => return return_error(env, &e),
    };
    let mut json = String::from("[");
    let mut first = true;
    for r in sigs.rules() {
        if !first { json.push(','); }
        first = false;
        json.push('{');
        json.push_str(&format!("\"id\":\"{}\"", json_escape(&r.id)));
        json.push_str(&format!(",\"name\":\"{}\"", json_escape(&r.name)));
        json.push_str(&format!(",\"category\":\"{}\"", r.category.as_str()));
        json.push_str(&format!(",\"severity\":\"{}\"", r.severity.as_str()));
        json.push_str(&format!(",\"description\":\"{}\"", json_escape(&r.description)));
        json.push('}');
    }
    json.push(']');
    return_string(env, &json)
}

// ---------------------------------------------------------------------------
// 4) engineVersion(): String  — semver
// ---------------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "system" fn Java_id_zai_apkdetector_NativeBridge_engineVersion(
    env: JNIEnvPtr,
    _class: jclass,
) -> jstring {
    return_string(env, env!("CARGO_PKG_VERSION"))
}

// ---------------------------------------------------------------------------
// JNI lifecycle
// ---------------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> jint {
    ensure_logger();
    log::info!("apk_detector native lib loaded");
    0x00010006 // JNI_VERSION_1_6
}
