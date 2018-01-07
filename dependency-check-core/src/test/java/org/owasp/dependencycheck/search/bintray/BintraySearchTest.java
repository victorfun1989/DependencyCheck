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
package org.owasp.dependencycheck.search.bintray;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.search.nexus.MavenArtifact;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;

import static org.junit.Assert.*;
import org.junit.BeforeClass;

/**
 * @author Jeremy Long
 */
public class BintraySearchTest extends BaseTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(BintraySearchTest.class);
    private BintraySearch searcher;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        searcher = new BintraySearch(getSettings());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullSha1() throws Exception {
        searcher.searchSha1(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalformedSha1() throws Exception {
        searcher.searchSha1("invalid");
    }

    /**
     * Test of searchSha1 method, of class BintraySearch. This test does
     * generate network traffic and communicates with a host you may not be able
     * to reach. Remove the @Ignore annotation if you want to test it anyway
     */
    @Test
    public void testSearchSha1() throws Exception {
        String sha1 = "9977a8d04e75609cf01badc4eb6a9c7198c4c5ea";
        BintrayArtifact[] result = searcher.searchSha1(sha1);
        assertEquals(1, result.length);
        assertEquals("maven-compiler-plugin-3.1.jar", result[0].getName());

        sha1 = "94A9CE681A42D0352B3AD22659F67835E560D107";
        result = searcher.searchSha1(sha1);
        assertEquals(2, result.length);

        sha1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        result = searcher.searchSha1(sha1);
        assertEquals(0, result.length);
    }

    /**
     * Test of parseResponse method, of class BintraySearch.
     */
    @Test
    public void testParseResponse() throws Exception {
        InputStream stream = BaseTest.getResourceAsStream(this, "bintray/scala-library-2.11.2.json");
        BintrayArtifact[] result = searcher.parseResponse(stream);
        assertEquals("2014-07-23T13:02:51.371Z", result[0].getCreated());
        assertEquals("scala-library-2.11.2.jar", result[0].getName());
        assertEquals("bintray", result[0].getOwner());
        assertEquals("org.scala-lang:scala-library", result[0].getPackageName());
        assertEquals("org/scala-lang/scala-library/2.11.2/scala-library-2.11.2.jar", result[0].getPath());
        assertEquals("jcenter", result[0].getRepo());
        assertEquals("4718c022bd5bd84705ddacec18072c351832bc20", result[0].getSha1());
        assertEquals("5545300", result[0].getSize());
        assertEquals("2.11.2", result[0].getVersion());
        
    }
}
