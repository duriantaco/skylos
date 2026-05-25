class AccountPolicy {
  String decide(String userId, String plan, String region, String coupon, String source, String actor, int score) {
    if (userId != null) {
      if (plan != null) {
        if (region != null) {
          if (source != null) {
            if (actor != null) {
              if (score > 10) {
                return "approve";
              }
            }
          }
        }
      }
    }
    return "review";
  }

  String helper(String userId) {
    return userId;
  }
}
