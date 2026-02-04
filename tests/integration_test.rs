//! Integration tests for lotl

#[test]
fn test_library_loads() {
    assert_eq!(lotl::name(), "lotl");
    assert_eq!(lotl::version(), "0.1.0");
}
