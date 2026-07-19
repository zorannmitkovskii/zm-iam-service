package zm.iam.common.exception;

/**
 * One field-level validation error. Emitted as an entry inside
 * {@link ApiError#fieldErrors()} so clients can bind messages back to
 * form fields instead of parsing a concatenated string.
 *
 * @param field   dotted JSON path to the offending field (e.g.
 *                {@code realms[1].clients[0].clientId})
 * @param message developer-friendly explanation from the constraint
 */
public record FieldError(String field, String message) {
}
