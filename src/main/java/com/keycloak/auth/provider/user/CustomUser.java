package com.keycloak.auth.provider.user;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.LegacyUserCredentialManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class CustomUser extends AbstractUserAdapter {
    private static final Logger log =  LoggerFactory.getLogger(CustomUser.class);

    private final String username;
    private String email;
    private String firstName;
    private String lastName;
    private Date birthDate;

    public CustomUser(KeycloakSession session, RealmModel realm,
                      ComponentModel storageProviderModel,
                      String username,
                      String email,
                      String firstName,
                      String lastName,
                      Date birthDate) {
        super(session, realm, storageProviderModel);
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.birthDate = birthDate;

    }

    public CustomUser(KeycloakSession session, RealmModel realm,
                      ComponentModel storageProviderModel,String username, String email, String firstName, String lastName) {
        super(session, realm, storageProviderModel);
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public CustomUser(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel, String username) {
        super(session, realm, storageProviderModel);
        this.username = username;
    }
    @Override
    public void setEmailVerified(boolean verified){
        try (Connection connection = DbUtil.getConnection(this.storageProviderModel)) {
            String sql = "UPDATE users SET isEmailVerified = ? WHERE username = ?";
            PreparedStatement pstmt = connection.prepareStatement(sql);
            pstmt.setBoolean(1, verified);
            pstmt.setString(2, getUsername());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void setEnabled(boolean enabled){
        try (Connection connection = DbUtil.getConnection(this.storageProviderModel)) {
            String sql = "UPDATE users SET enabled = ? WHERE username = ?";
            PreparedStatement pstmt = connection.prepareStatement(sql);
            pstmt.setBoolean(1, enabled);
            pstmt.setString(2, getUsername());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getFirstName() {
        return firstName;
    }

    @Override
    public String getLastName() {
        return lastName;
    }

    @Override
    public String getEmail() {
        return email;
    }

    public Date getBirthDate() {
        return birthDate;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, getUsername());
        attributes.add(UserModel.EMAIL,getEmail());
        attributes.add(UserModel.FIRST_NAME,getFirstName());
        attributes.add(UserModel.LAST_NAME,getLastName());
        //attributes.add("birthDate",getBirthDate().toString());
        return attributes;
    }
    @Override
    public void setAttribute(String name, List<String> values) {
        try (Connection connection = DbUtil.getConnection(this.storageProviderModel)) {
            String sql = "INSERT INTO users (username, email, first_name, last_name) VALUES (?, ?, ?, ?)";
            PreparedStatement pstmt = connection.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, getUsername());
            pstmt.setString(2, getEmail());
            pstmt.setString(3, getFirstName());
            pstmt.setString(4, getLastName());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }


    static class Builder {
        private final KeycloakSession session;
        private final RealmModel realm;
        private final ComponentModel storageProviderModel;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private Date birthDate;

        Builder(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel,String username) {
            this.session = session;
            this.realm = realm;
            this.storageProviderModel = storageProviderModel;
            this.username = username;
        }

        CustomUser.Builder email(String email) {
            this.email = email;
            return this;
        }

        CustomUser.Builder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        CustomUser.Builder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        CustomUser.Builder birthDate(Date birthDate) {
            this.birthDate = birthDate;
            return this;
        }

        CustomUser build() {
            return new CustomUser(
                    session,
                    realm,
                    storageProviderModel,
                    username,
                    email,
                    firstName,
                    lastName,
                    birthDate);

        }
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return new LegacyUserCredentialManager(session, realm, this);
    }
}