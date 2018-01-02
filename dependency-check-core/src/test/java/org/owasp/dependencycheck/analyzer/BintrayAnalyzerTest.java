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

import mockit.Expectations;
import mockit.Mocked;
import org.junit.Test;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.bintray.BintraySearch;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Tests for the BintrayAnalyzer.
 */
public class BintrayAnalyzerTest {

    private static final String SHA1_SUM = "my-sha1-sum";

    @Test(expected = FileNotFoundException.class)
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsRethrowsFileNotFoundException(@Mocked final BintraySearch search,
            @Mocked final Dependency dependency)
            throws IOException {

        BintrayAnalyzer instance = new BintrayAnalyzer();
        instance.setBintraySearch(search);
        specifySha1SumFor(dependency);

        new Expectations() {
            {
                search.searchSha1(SHA1_SUM);
                result = new FileNotFoundException("Artifact not found in Bintray");
            }
        };

        instance.fetchArtifacts(dependency);
    }

    @Test(expected = IOException.class)
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsAlwaysThrowsIOException(@Mocked final BintraySearch search,
            @Mocked final Dependency dependency)
            throws IOException {

        BintrayAnalyzer instance = new BintrayAnalyzer();
        instance.setBintraySearch(search);
        specifySha1SumFor(dependency);

        new Expectations() {
            {
                search.searchSha1(SHA1_SUM);
                result = new IOException("no internet connection");
            }
        };

        instance.fetchArtifacts(dependency);
    }

    @Test(expected = AnalysisException.class)
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsAlwaysThrowsIOExceptionLetsTheAnalysisFail(
            @Mocked final BintraySearch search, @Mocked final Dependency dependency)
            throws AnalysisException, IOException {

        BintrayAnalyzer instance = new BintrayAnalyzer();
        instance.setBintraySearch(search);
        specifySha1SumFor(dependency);

        new Expectations() {
            {
                search.searchSha1(SHA1_SUM);
                result = new IOException("no internet connection");
            }
        };

        instance.analyze(dependency, null);
    }

    /**
     * Specifies the mock dependency's SHA1 sum.
     *
     * @param dependency then dependency
     */
    @SuppressWarnings("PMD.NonStaticInitializer")
    private void specifySha1SumFor(final Dependency dependency) {
        new Expectations() {
            {
                dependency.getSha1sum();
                returns(SHA1_SUM, SHA1_SUM);
            }
        };
    }
}
