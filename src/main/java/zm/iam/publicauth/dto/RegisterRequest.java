package zm.iam.publicauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** POST /public/users/register — creates a disabled user + issues a 6-digit
 *  verification code + emails it. Same shape as ivy-events-be today. */
public record RegisterRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8) String password,
        String firstName,
        String lastName,
        /** Optional — used if Origin header can't resolve to a realm. */
        String appId,
        /**
         * Personal or organizer. Absent means {@link AccountType#PERSONAL}, so
         * an older client that does not send it keeps working and cannot
         * accidentally create an agency.
         */
        AccountType accountType,
        /**
         * The agency's name. Required for {@link AccountType#ORGANIZER} and
         * ignored otherwise — an organization with no name is a row nobody can
         * identify in a registry other products read.
         */
        @Size(max = 200) String organizationName
) {

    public AccountType accountTypeOrDefault() {
        return accountType == null ? AccountType.PERSONAL : accountType;
    }

    public boolean isOrganizer() {
        return accountTypeOrDefault() == AccountType.ORGANIZER;
    }
}
