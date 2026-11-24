package zm.iam.publicauth.dto;

/**
 * What kind of account somebody is asking for at signup.
 *
 * <p>Only personal accounts can be created here. {@link #ORGANIZER} stays in the
 * enum so a client that still offers it gets a clear refusal rather than a
 * parse error, or a personal account nobody asked for.
 */
public enum AccountType {

    /** Plans their own events. Gets USER, owns the events they create. */
    PERSONAL,

    /** Plans events for clients. Refused at signup. */
    ORGANIZER
}
