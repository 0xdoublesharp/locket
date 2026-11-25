use std::cell::Cell;
use std::ptr;

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{ClassType, msg_send};
use objc2_foundation::NSString;

use super::*;

#[test]
fn framework_reply_converts_success_and_rejections_without_a_prompt() {
    let (tx, rx) = mpsc::channel();
    let reply = evaluation_reply(tx);
    let invalidated = Cell::new(false);
    let invalidate = || invalidated.set(true);
    reply.call((Bool::YES, ptr::null_mut()));
    assert!(matches!(await_evaluation(&rx, Duration::ZERO, invalidate), Ok(true)));

    reply.call((Bool::NO, ptr::null_mut()));
    assert!(matches!(
        await_evaluation(&rx, Duration::ZERO, invalidate),
        Err(LocalAuthError::Rejected(message)) if message == "user rejected local user verification"
    ));

    let domain = NSString::from_str("LocketTestLocalAuth");
    // SAFETY: this synthetic NSError uses a live domain and no user-info dictionary.
    let error: Retained<NSError> = unsafe {
        msg_send![NSError::class(), errorWithDomain: &*domain, code: 17_isize,
            userInfo: ptr::null::<AnyObject>()]
    };
    let description = error.localizedDescription().to_string();
    // Retain the synthetic NSError until the block has copied its description.
    reply.call((Bool::NO, ptr::from_ref(&*error).cast_mut()));
    drop(error);
    assert!(matches!(
        await_evaluation(&rx, Duration::ZERO, invalidate),
        Err(LocalAuthError::Rejected(message)) if message == description
    ));
    assert!(!invalidated.get());
}

#[test]
fn framework_timeout_invalidates_and_late_reply_is_harmless() {
    let (tx, rx) = mpsc::channel();
    let reply = evaluation_reply(tx);
    let invalidations = Cell::new(0);
    assert!(matches!(
        await_evaluation(&rx, Duration::ZERO, || invalidations.set(invalidations.get() + 1)),
        Err(LocalAuthError::Timeout)
    ));
    assert_eq!(invalidations.get(), 1);
    drop(rx);
    reply.call((Bool::YES, ptr::null_mut()));

    let (tx, rx) = mpsc::channel();
    drop(tx);
    assert!(matches!(
        await_evaluation(&rx, Duration::ZERO, || invalidations.set(invalidations.get() + 1)),
        Err(LocalAuthError::Framework(message)) if message.contains("channel closed")
    ));
    assert_eq!(invalidations.get(), 1);
}
