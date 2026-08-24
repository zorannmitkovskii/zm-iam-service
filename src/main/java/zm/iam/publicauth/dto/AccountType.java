package zm.iam.publicauth.dto;

/**
 * What kind of account somebody is asking for at signup.
 *
 * <p>Two different products behind one form. Someone planning their own wedding
 * and an agency planning other people's weddings need the same login and almost
 * nothing else the same — the agency needs an organization to own its clients,
 * its pipeline and its branding, and the couple needs none of that.
 *
 * <p>Asked at signup rather than inferred later, because the alternative is what
 * this replaces: every account was created personal, and an agency then hit a
 * wall of 403s from the CRM with nothing on screen explaining that the problem
 * was an account type chosen for them.
 */
public enum AccountType {

    /** Plans their own events. Gets USER, owns the events they create. */
    PERSONAL,

    /** Plans events for clients. Gets an organization and administers it. */
    ORGANIZER;

    /** The safe reading of a missing or unknown value. An account that should
     *  have been an agency is a support ticket; an agency created by accident
     *  is a tenant in the registry nobody asked for. */
    public static AccountType orPersonal(String raw) {
        if (raw == null || raw.isBlank()) {
            return PERSONAL;
        }
        try {
            return valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException unknown) {
            return PERSONAL;
        }
    }
}
