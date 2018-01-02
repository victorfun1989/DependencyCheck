/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.bintray;

import com.google.gson.Gson;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class of methods to search Maven Central via Central.
 *
 * @author colezlaw
 */
@ThreadSafe
public class BintraySearch {

    /**
     * The URL for the Central service.
     */
    private final String rootURL;

    /**
     * The Central Search Query.
     */
    private final String query;
    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(BintraySearch.class);
    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Creates a NexusSearch for the given repository URL.
     *
     * @param settings the configured settings
     * @throws MalformedURLException thrown if the configured URL is invalid
     */
    public BintraySearch(Settings settings) throws MalformedURLException {
        this.settings = settings;

        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_BINTRAY_URL);
        LOGGER.debug("Bintray Search URL: {}", searchUrl);
        if (isInvalidURL(searchUrl)) {
            throw new MalformedURLException(String.format("The configured bintray analyzer URL is invalid: %s", searchUrl));
        }
        this.rootURL = searchUrl;
        final String queryStr = settings.getString(Settings.KEYS.ANALYZER_BINTRAY_QUERY);
        LOGGER.debug("Bintray Search Query: {}", queryStr);
        if (!queryStr.matches("^%s.*%s.*$")) {
            final String msg = String.format("The configured bintray analyzer query parameter is invalid (it must have two %%s): %s", queryStr);
            throw new MalformedURLException(msg);
        }
        this.query = queryStr;
        LOGGER.debug("Bintray Search Full URL: {}", String.format(query, rootURL, "[SHA1]"));
    }

    /**
     * Searches the configured Bintray URL for the given SHA1 hash. If the
     * artifact is found, a <code>MavenArtifact</code> is populated with the
     * GAV.
     *
     * @param sha1 the SHA-1 hash string for which to search
     * @return the populated Maven GAV.
     * @throws FileNotFoundException if the specified artifact is not found
     * @throws IOException if it's unable to connect to the specified repository
     */
    public BintrayArtifact[] searchSha1(String sha1) throws IOException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }
        HttpURLConnection conn = getConnection(sha1);
        if (conn.getResponseCode() == 200) {
            return parseResponse(conn.getInputStream());
        } else {
            final String errorMessage = "Could not connect to bintray api (" + conn.getResponseCode() + "): " + conn.getResponseMessage();
            throw new IOException(errorMessage);
        }
    }

    private HttpURLConnection getConnection(String sha1) throws URLConnectionFailureException, MalformedURLException, IOException {
        final URL url = new URL(String.format(query, rootURL, sha1));
        LOGGER.debug("Searching Bintray url {}", url);
        final URLConnectionFactory factory = new URLConnectionFactory(settings);
        final HttpURLConnection conn = factory.createHttpURLConnection(url);
        conn.setDoOutput(true);
        conn.addRequestProperty("Accept", "application/json");
        conn.connect();
        return conn;
    }

    protected BintrayArtifact[] parseResponse(InputStream stream) throws IOException, FileNotFoundException {
        Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
        return new Gson().fromJson(reader, BintrayArtifact[].class);
    }

    /**
     * Tests to determine if the given URL is <b>invalid</b>.
     *
     * @param url the URL to evaluate
     * @return true if the URL is malformed; otherwise false
     */
    private boolean isInvalidURL(String url) {
        try {
            final URL u = new URL(url);
            u.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.trace("URL is invalid: {}", url);
            return true;
        }
        return false;
    }
}
