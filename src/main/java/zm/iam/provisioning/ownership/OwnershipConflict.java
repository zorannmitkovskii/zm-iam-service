package zm.iam.provisioning.ownership;

/**
 * One row of the 409 response body — describes exactly which resource
 * the caller cannot touch and who does own it.
 */
public record OwnershipConflict(
        ResourceType conflictType,
        String realm,
        String resource,
        String ownerService,
        String message
) {}
