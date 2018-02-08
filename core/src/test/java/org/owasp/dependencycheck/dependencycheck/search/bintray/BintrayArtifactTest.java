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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.search.bintray;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author jeremy
 */
public class BintrayArtifactTest extends BaseTest {

    BintrayArtifact instance;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        BintraySearch searcher = new BintraySearch(getSettings());
        InputStream stream = BaseTest.getResourceAsStream(this, "bintray/scala-library-2.11.2.json");
        BintrayArtifact[] result = searcher.parseResponse(stream);
        instance = result[0];
    }

    /**
     * Test of getName method, of class BintrayArtifact.
     */
    @Test
    public void testGetName() {
        String expResult = "scala-library-2.11.2.jar";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getPath method, of class BintrayArtifact.
     */
    @Test
    public void testGetPath() {
        String expResult = "org/scala-lang/scala-library/2.11.2/scala-library-2.11.2.jar";
        String result = instance.getPath();
        assertEquals(expResult, result);
    }

    /**
     * Test of getRepo method, of class BintrayArtifact.
     */
    @Test
    public void testGetRepo() {
        String expResult = "jcenter";
        String result = instance.getRepo();
        assertEquals(expResult, result);
    }

    /**
     * Test of getPackageName method, of class BintrayArtifact.
     */
    @Test
    public void testGetPackageName() {
        String expResult = "org.scala-lang:scala-library";
        String result = instance.getPackageName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getVersion method, of class BintrayArtifact.
     */
    @Test
    public void testGetVersion() {
        String expResult = "2.11.2";
        String result = instance.getVersion();
        assertEquals(expResult, result);
    }

    /**
     * Test of getOwner method, of class BintrayArtifact.
     */
    @Test
    public void testGetOwner() {
        String expResult = "bintray";
        String result = instance.getOwner();
        assertEquals(expResult, result);
    }

    /**
     * Test of getCreated method, of class BintrayArtifact.
     */
    @Test
    public void testGetCreated() {
        String expResult = "2014-07-23T13:02:51.371Z";
        String result = instance.getCreated();
        assertEquals(expResult, result);
    }

    /**
     * Test of getSize method, of class BintrayArtifact.
     */
    @Test
    public void testGetSize() {
        String expResult = "5545300";
        String result = instance.getSize();
        assertEquals(expResult, result);
    }

    /**
     * Test of getSha1 method, of class BintrayArtifact.
     */
    @Test
    public void testGetSha1() {
        String expResult = "4718c022bd5bd84705ddacec18072c351832bc20";
        String result = instance.getSha1();
        assertEquals(expResult, result);
    }

    /**
     * Test of getCoordinates method, of class BintrayArtifact.
     *
     * @throws java.net.MalformedURLException
     */
    @Test
    public void testGetCoordinates() throws MalformedURLException, IOException {
        String expResult = "org.scala-lang:scala-library:2.11.2";
        String result = instance.getCoordinates();
        assertEquals(expResult, result);

        BintraySearch searcher = new BintraySearch(getSettings());
        InputStream stream = BaseTest.getResourceAsStream(this, "bintray/spring-core-3.0.0.RELEASE.json");
        BintrayArtifact[] ba = searcher.parseResponse(stream);

        expResult = "org.springframework:spring-core:3.0.0.RELEASE";
        result = ba[0].getCoordinates();
        assertEquals(expResult, result);

        expResult = "org.sonatype.aether:aether-util:1.7";
        stream = BaseTest.getResourceAsStream(this, "bintray/aether-util-1.7.json");
        ba = searcher.parseResponse(stream);
        result = ba[0].getCoordinates();
        assertEquals(expResult, result);
    }

    /**
     * Test of getArtifactUrl method, of class BintrayArtifact.
     */
    @Test
    public void testGetArtifactUrl() {
        String expResult = "https://dl.bintray.com/bintray/jcenter/org/scala-lang/scala-library/2.11.2/scala-library-2.11.2.jar";
        String result = instance.getArtifactUrl();
        assertEquals(expResult, result);
    }

    /**
     * Test of getPomUrl method, of class BintrayArtifact.
     */
    @Test
    public void testGetPomUrl() {
        String expResult = "https://dl.bintray.com/bintray/jcenter/org/scala-lang/scala-library/2.11.2/scala-library-2.11.2.pom";
        String result = instance.getPomUrl();
        assertEquals(expResult, result);
    }

}
