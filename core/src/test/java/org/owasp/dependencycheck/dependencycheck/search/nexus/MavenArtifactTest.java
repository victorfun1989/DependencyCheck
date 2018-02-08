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
package org.owasp.dependencycheck.search.nexus;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jeremy
 */
public class MavenArtifactTest {
    /**
     * Test of toString method, of class MavenArtifact.
     */
    @Test
    public void testToString() {
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        String expResult = "groupId:artifactId:version";
        String result = instance.toString();
        assertEquals(expResult, result);
    }

    /**
     * Test of setGroupId method, of class MavenArtifact.
     */
    @Test
    public void testSetGroupId() {
        String groupId = "updated";
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        instance.setGroupId(groupId);
        String expResult = "updated";
        String result = instance.getGroupId();
        assertEquals(expResult, result);
    }

    /**
     * Test of getGroupId method, of class MavenArtifact.
     */
    @Test
    public void testGetGroupId() {
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        String expResult = "groupId";
        String result = instance.getGroupId();
        assertEquals(expResult, result);
    }

    /**
     * Test of setArtifactId method, of class MavenArtifact.
     */
    @Test
    public void testSetArtifactId() {
        String artifactId = "updated";
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        instance.setArtifactId(artifactId);
        String expResult = "updated";
        String result = instance.getArtifactId();
        assertEquals(expResult, result);
    }

    /**
     * Test of getArtifactId method, of class MavenArtifact.
     */
    @Test
    public void testGetArtifactId() {
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        String expResult = "artifactId";
        String result = instance.getArtifactId();
        assertEquals(expResult, result);
    }

    /**
     * Test of setVersion method, of class MavenArtifact.
     */
    @Test
    public void testSetVersion() {
        String version = "updated";
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        instance.setVersion(version);
        String expResult = "updated";
        String result = instance.getVersion();
        assertEquals(expResult, result);
    }

    /**
     * Test of getVersion method, of class MavenArtifact.
     */
    @Test
    public void testGetVersion() {
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        String expResult = "version";
        String result = instance.getVersion();
        assertEquals(expResult, result);
    }

    /**
     * Test of setArtifactUrl method, of class MavenArtifact.
     */
    @Test
    public void testSetArtifactUrl() {
        String artifactUrl = "https://some.valid.org/path";
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        instance.setArtifactUrl(artifactUrl);
        String expResult = "https://some.valid.org/path";
        String result = instance.getArtifactUrl();
        assertEquals(expResult, result);
    }

    /**
     * Test of getArtifactUrl method, of class MavenArtifact.
     */
    @Test
    public void testGetArtifactUrl() {
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        String result = instance.getArtifactUrl();
        assertNull(result);
        instance = new MavenArtifact("groupId", "artifactId", "version", false, false, false);
        result = instance.getArtifactUrl();
        assertNull(result);
        instance = new MavenArtifact("groupId", "artifactId", "version", false, true, false);
        result = instance.getArtifactUrl();
        assertNull(result);
        instance = new MavenArtifact("groupId", "artifactId", "version", false, false, true);
        result = instance.getArtifactUrl();
        assertNull(result);
        instance = new MavenArtifact("groupId", "artifactId", "version", false, true, true);
        result = instance.getArtifactUrl();
        assertNull(result);
        
        instance = new MavenArtifact("groupId", "artifactId", "version", true, false, true);
        String expResult = "https://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.jar";
        result = instance.getArtifactUrl();
        assertEquals(expResult, result);
        instance = new MavenArtifact("groupId", "artifactId", "version", true, false, false);
        expResult = "http://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.jar";
        result = instance.getArtifactUrl();
        assertEquals(expResult, result);
        
        instance = new MavenArtifact("groupId", "artifactId", "version", true, true, true);
        expResult = "https://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.jar";
        result = instance.getArtifactUrl();
        assertEquals(expResult, result);
        instance = new MavenArtifact("groupId", "artifactId", "version", true, true, false);
        expResult = "http://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.jar";
        result = instance.getArtifactUrl();
        assertEquals(expResult, result);
    }

    /**
     * Test of getPomUrl method, of class MavenArtifact.
     */
    @Test
    public void testGetPomUrl() {
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        String result = instance.getPomUrl();
        assertNull(result);
        instance = new MavenArtifact("groupId", "artifactId", "version", false, false, false);
        result = instance.getPomUrl();
        assertNull(result);
        instance = new MavenArtifact("groupId", "artifactId", "version", true, false, false);
        result = instance.getPomUrl();
        assertNull(result);
        instance = new MavenArtifact("groupId", "artifactId", "version", false, false, true);
        result = instance.getPomUrl();
        assertNull(result);
        instance = new MavenArtifact("groupId", "artifactId", "version", true, false, true);
        result = instance.getPomUrl();
        assertNull(result);
        
        
        instance = new MavenArtifact("groupId", "artifactId", "version", false, true, true);
        String expResult = "https://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.pom";
        result = instance.getPomUrl();
        assertEquals(expResult, result);
        instance = new MavenArtifact("groupId", "artifactId", "version", false, true, false);
        expResult = "http://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.pom";
        result = instance.getPomUrl();
        assertEquals(expResult, result);
        instance = new MavenArtifact("groupId", "artifactId", "version", true, true, true);
        expResult = "https://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.pom";
        result = instance.getPomUrl();
        assertEquals(expResult, result);
        instance = new MavenArtifact("groupId", "artifactId", "version", true, true, false);
        expResult = "http://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.pom";
        result = instance.getPomUrl();
        assertEquals(expResult, result);
    }

    /**
     * Test of setPomUrl method, of class MavenArtifact.
     */
    @Test
    public void testSetPomUrl() {
        String pomUrl = "https://some.valid.org/path";
        MavenArtifact instance = new MavenArtifact("groupId", "artifactId", "version");
        instance.setPomUrl(pomUrl);
        String expResult = "https://some.valid.org/path";
        String result = instance.getPomUrl();
        assertEquals(expResult, result);
    }
}
