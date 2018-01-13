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

import java.io.File;
import java.io.FileFilter;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Dependency;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.owasp.dependencycheck.BaseTest;

/**
 * Tests for the BintrayAnalyzer.
 */
public class BintrayAnalyzerTest extends BaseTest {

    private BintrayAnalyzer instance;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        instance = new BintrayAnalyzer();
        instance.initialize(getSettings());
        instance.prepareFileTypeAnalyzer(null);
    }

    /**
     * Test of getName method, of class BintrayAnalyzer.
     */
    @Test
    public void testGetName() {
        String expResult = "Bintray Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class BintrayAnalyzer.
     */
    @Test
    public void testGetAnalyzerEnabledSettingKey() {
        String expResult = "analyzer.bintray.enabled";
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class BintrayAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getFileFilter method, of class BintrayAnalyzer.
     */
    @Test
    public void testGetFileFilter() {
        FileFilter result = instance.getFileFilter();
        assertTrue(result.accept(new File("test.jar")));
        assertFalse(result.accept(new File("test.zip")));
    }

    /**
     * Test of analyzeDependency method, of class BintrayAnalyzer.
     */
    @Test
    public void testAnalyzeDependency() throws Exception {
        Dependency dependency = new Dependency();
        dependency.setSha1sum("4f268922155ff53fb7b28aeca24fb28d5a439d95");
        assertTrue(dependency.getIdentifiers().isEmpty());
        instance.analyzeDependency(dependency, null);
        assertFalse(dependency.getIdentifiers().isEmpty());
    }
}
