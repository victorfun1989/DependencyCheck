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

import com.google.gson.annotations.SerializedName;
import com.sun.xml.internal.ws.util.VersionUtil;
import org.apache.commons.io.FilenameUtils;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;

/**
 *
 * @author jeremy long
 */
public class BintrayArtifact {

    /**
     * The path to the JCenter repo formated for use in String.format() so one
     * can easily obtain the URL for an artifact.
     */
    private static final String JCENTER_PATH_FORMAT = "https://dl.bintray.com/%s/%s/%s";
    /**
     * The name of the artifact.
     */
    @SerializedName("name")
    private String name;
    /**
     * The path of the artifact.
     */
    @SerializedName("path")
    private String path;
    /**
     * The repository where the artifact can be found.
     */
    @SerializedName("repo")
    private String repo;
    /**
     * The package name of the artifact.
     */
    @SerializedName("package")
    private String packageName;
    /**
     * The version of the artifact.
     */
    @SerializedName("version")
    private String version;
    /**
     * The owner of the artifact.
     */
    @SerializedName("owner")
    private String owner;
    /**
     * The created timestamp.
     */
    @SerializedName("created")
    private String created;
    /**
     * The size of the artifact.
     */
    @SerializedName("size")
    private String size;
    /**
     * The SHA1 hash of the artifact.
     */
    @SerializedName("sha1")
    private String sha1;

    /**
     * Returns the name of the artifact.
     *
     * @return the name of the artifact
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the path to the artifact
     *
     * @return the path to the artifact
     */
    public String getPath() {
        return path;
    }

    /**
     * Returns the repository where the artifact is located.
     *
     * @return the repository where the artifact is located
     */
    public String getRepo() {
        return repo;
    }

    /**
     * Returns the package name of the artifact.
     *
     * @return Returns the package name of the artifact
     */
    public String getPackageName() {
        return packageName;
    }

    /**
     * Returns the version of the artifact.
     *
     * @return the version of the artifact
     */
    public String getVersion() {
        return version;
    }

    /**
     * Returns the owner of the artifact.
     *
     * @return the owner of the artifact
     */
    public String getOwner() {
        return owner;
    }

    /**
     * Returns the timestamp of when the artifact package was created.
     *
     * @return the timestamp of when the artifact package was created
     */
    public String getCreated() {
        return created;
    }

    /**
     * Returns the size of the artifact.
     *
     * @return the size of the artifact
     */
    public String getSize() {
        return size;
    }

    /**
     * Returns the SHA1 hash of the artifact.
     *
     * @return the SHA1 hash of the artifact
     */
    public String getSha1() {
        return sha1;
    }

    /**
     * Returns the full coordinates of the artifact - package path + version.
     *
     * @return the full coordinates of the artifact - package path + version
     */
    public String getCoordinates() {
        if (path==null) {
            return null;
        }
        final String[] parts = path.split("/");
        if (parts.length<4) {
            return null;
        }
        final String cordVersion = parts[parts.length-2];
        final String cordArtifactId = parts[parts.length-3];
        StringBuilder sb = new StringBuilder();
        String period="";
        for (int i=0;i<parts.length-3;i++) {
            sb.append(period).append(parts[i]);
            if (period.isEmpty()) {
                period = ".";
            }
        }
        return  String.format("%s:%s:%s", sb.toString(), cordArtifactId, cordVersion);
        
//        if (!packageName.contains(":") && name != null) {
//            int pos = FilenameUtils.indexOfExtension(name);
//            String artifactId;
//            if (pos > 1) {
//                artifactId = name.substring(0, pos);
//            } else {
//                artifactId = name;
//            }
//            if (artifactId.endsWith(version)) {
//                artifactId = artifactId.substring(0, artifactId.length() - version.length() - 1);
//            } else {
//                final String dependencyVersion = DependencyVersionUtil.parseVersion(artifactId).toString();
//                if (dependencyVersion!=null) {
//                    artifactId = artifactId.substring(0, artifactId.length() - dependencyVersion.length() - 1);    
//                }
//            }
//            if (path != null) {
//                String tmp = path.replace("/", ".");
//                pos = tmp.lastIndexOf("." + artifactId + ".");
//                if (pos > 0) {
//                    tmp = tmp.substring(0, pos);
//                    return String.format("%s:%s:%s", tmp, artifactId, version);
//                }
//            }
//
//            return String.format("%s:%s:%s", packageName, artifactId, version);
//        }
//        return String.format("%s:%s", packageName, version);
    }

    public String getArtifactUrl() {
        if (owner != null && repo != null && path != null && !path.isEmpty()) {
            return String.format(JCENTER_PATH_FORMAT, owner, repo, path);
        }
        return null;
    }

    public String getPomUrl() {
        if (owner != null && repo != null && path != null && path.endsWith(".jar")) {
            final String pomPath = path.substring(0, path.length() - 3) + "pom";
            return String.format(JCENTER_PATH_FORMAT, owner, repo, pomPath);
        }
        return null;
    }

}
