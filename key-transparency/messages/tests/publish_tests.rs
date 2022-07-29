use test_utils::{certificate, committee, notification, proof, votes};

#[tokio::test]
async fn verify_notification() {
    let (root, _, _) = proof().await;
    let notification = notification().await;
    assert!(notification.verify(&committee(0), &root).await.is_ok());
}

#[tokio::test]
async fn verify_bad_notification() {
    let (_, end_root, _) = proof().await;
    let notification = notification().await;
    assert!(notification.verify(&committee(0), &end_root).await.is_err());
}

#[tokio::test]
async fn verify_vote() {
    let vote = votes().await.pop().unwrap();
    assert!(vote.verify(&committee(0)).is_ok());
}

#[tokio::test]
async fn verify_certificate() {
    let certificate = certificate().await;
    assert!(certificate.verify(&committee(0)).is_ok());
}
