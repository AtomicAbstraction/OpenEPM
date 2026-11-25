package dev.openepm.identity;

import java.util.List;
import org.keycloak.models.GroupModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

public final class OpenEpmGroupIdsMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper {
    private static final String CLAIM = "openepm_group_ids";
    // Emit one extra ID on overflow so Open EPM refuses the token instead of
    // authorizing against a silently truncated set.
    private static final int OVERFLOW_LIMIT = 101;

    @Override
    public String getId() {
        return "openepm-group-id-mapper";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Open EPM group IDs";
    }

    @Override
    public String getHelpText() {
        return "Include immutable IDs of managed Open EPM groups in the access token.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mapping, UserSessionModel session) {
        try (var groups = session.getUser().getGroupsStream()) {
            var ids = groups
                    .filter(group -> "openepm-group-v1".equals(group.getFirstAttribute("openepm_kind")))
                    .map(GroupModel::getId)
                    .distinct()
                    .limit(OVERFLOW_LIMIT)
                    .sorted()
                    .toList();
            token.getOtherClaims().put(CLAIM, ids);
        }
    }
}
