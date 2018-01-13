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
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.search.bintray.BintraySearch;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.xml.pom.PomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.search.bintray.BintrayArtifact;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Analyzer which will attempt to locate a dependency, and the GAV information,
 * by querying Bintray for the dependency's SHA-1 digest.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class BintrayAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(BintrayAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Bintray Analyzer";

    /**
     * The phase in which this analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The types of files on which this will work.
     */
    private static final String SUPPORTED_EXTENSIONS = "jar";

    /**
     * The searcher itself.
     */
    private BintraySearch searcher;

    /**
     * Initializes the analyzer with the configured settings.
     *
     * @param settings the configured settings to use
     */
    @Override
    public void initialize(Settings settings) {
        super.initialize(settings);
        setEnabled(checkEnabled());
    }

    /**
     * Determines if this analyzer is enabled.
     *
     * @return <code>true</code> if the analyzer is enabled; otherwise
     * <code>false</code>
     */
    private boolean checkEnabled() {
        boolean retVal = false;

        try {
            if (getSettings().getBoolean(Settings.KEYS.ANALYZER_BINTRAY_ENABLED)) {
                if (!getSettings().getBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED)
                        || NexusAnalyzer.DEFAULT_URL.equals(getSettings().getString(Settings.KEYS.ANALYZER_NEXUS_URL))) {
                    LOGGER.debug("Enabling the Bintray analyzer");
                    retVal = true;
                } else {
                    LOGGER.info("Nexus analyzer is enabled, disabling the Bintray Analyzer");
                }
            } else {
                LOGGER.info("Bintray analyzer disabled");
            }
        } catch (InvalidSettingException ise) {
            LOGGER.warn("Invalid setting. Disabling the Bintray analyzer");
        }
        return retVal;
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        LOGGER.debug("Initializing Bintray analyzer");
        LOGGER.debug("Bintray analyzer enabled: {}", isEnabled());
        if (isEnabled()) {
            try {
                searcher = new BintraySearch(getSettings());
            } catch (MalformedURLException ex) {
                setEnabled(false);
                throw new InitializationException("The configured URL to Bintray API is malformed", ex);
            }
        }
    }

    /**
     * Returns the analyzer's name.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the key used in the properties file to to reference the
     * analyzer's enabled property.
     *
     * @return the analyzer's enabled property setting key.
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_BINTRAY_ENABLED;
    }

    /**
     * Returns the analysis phase under which the analyzer runs.
     *
     * @return the phase under which the analyzer runs
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(SUPPORTED_EXTENSIONS).build();

    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Performs the analysis.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine
     * @throws AnalysisException when there's an exception during analysis
     */
    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            final BintrayArtifact[] bas = fetchArtifacts(dependency);
            final Confidence confidence = bas.length > 1 ? Confidence.HIGH : Confidence.HIGHEST;
            for (BintrayArtifact ba : bas) {
                LOGGER.debug("Bintray analyzer found artifact ({}) for dependency ({})", ba.getPackageName(), dependency.getFileName());
                dependency.addAsEvidence("bintray", ba, confidence);
                boolean pomAnalyzed = false;
                for (Evidence e : dependency.getEvidence(EvidenceType.VENDOR)) {
                    if ("pom".equals(e.getSource())) {
                        pomAnalyzed = true;
                        break;
                    }
                }
                if (!pomAnalyzed && ba.getPomUrl() != null) {
                    File pomFile = null;
                    try {
                        final File baseDir = getSettings().getTempDirectory();
                        pomFile = File.createTempFile("pom", ".xml", baseDir);
                        if (!pomFile.delete()) {
                            LOGGER.warn("Unable to fetch pom.xml for {} from Bintray; "
                                    + "this could result in undetected CPE/CVEs.", dependency.getFileName());
                            LOGGER.debug("Unable to delete temp file");
                        }
                        LOGGER.debug("Downloading {}", ba.getPomUrl());
                        final Downloader downloader = new Downloader(getSettings());
                        downloader.fetchFile(new URL(ba.getPomUrl()), pomFile);
                        PomUtils.analyzePOM(dependency, pomFile);

                    } catch (DownloadFailedException ex) {
                        LOGGER.warn("Unable to download pom.xml for {} from Bintray; "
                                + "this could result in undetected CPE/CVEs.", dependency.getFileName());
                    } finally {
                        if (pomFile != null && pomFile.exists() && !FileUtils.deleteQuietly(pomFile)) {
                            LOGGER.debug("Failed to delete temporary pom file {}", pomFile.toString());
                            pomFile.deleteOnExit();
                        }
                    }
                }
            }
        } catch (IllegalArgumentException iae) {
            LOGGER.info("invalid sha1-hash on {}", dependency.getFileName());
        } catch (FileNotFoundException fnfe) {
            LOGGER.debug("Artifact not found in repository: '{}", dependency.getFileName());
        } catch (IOException ioe) {
            final String message = "Could not connect to Bintray API. Analysis failed.";
            LOGGER.error(message, ioe);
            throw new AnalysisException(message, ioe);
        } catch (Throwable ex) {
            LOGGER.error("---------------------------" + ex.getMessage(), ex);
            throw ex;
        }
    }

    /**
     * Downloads the information about the dependency from Bintray.
     *
     * @param dependency the dependency to analyze
     * @return the downloaded list of MavenArtifacts
     * @throws FileNotFoundException if the specified artifact is not found
     * @throws IOException if connecting to Bintray failed
     */
    private BintrayArtifact[] fetchArtifacts(Dependency dependency) throws IOException {
        return searcher.searchSha1(dependency.getSha1sum());
    }
}
