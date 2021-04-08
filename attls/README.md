This program and the accompanying materials are made available under the terms of the Eclipse Public License v2.0 which accompanies this distribution, and is available at https://www.eclipse.org/legal/epl-v20.html

SPDX-License-Identifier: EPL-2.0

## Library AT-TLS


Java library providing native calls about AT-TLS. 

This library can be imported in the Java project without Spring, which realizes secure communication via AT-TLS. 

## Using the Library

```gradle
plugins {
    id 'java'
}

dependencies {
    implementation 'org.zowe:zowe-attls:<replace with desired version>'
}
```


## How to enable the library

The base part of library is native code. At first, you should handle it:

 1. Extract SO library. SO file is located in JAR file at `lib/libzowe-attls.so` for 64-bit Java, or `lib/libzowe-attls-31.so` for 31-bit Java.

 2. Copy SO library to USS and set attributes of file:

    ```sh
    chmod a+x <library.so>
    extattr +p <library.so>
    ```

 3. Include the directory into the library path, see Java attribute `-Djava.library.path=<path to folder with SO libraries>`

## How to use library

The library provides IOCTL calls. Those calls support:
 - getting information about AT-TLS session (Aware mode)
 - controlling AT-TLS security for a connection (Control mode)

**Note**: Any application can be AT-TLS aware, for control mode the AT-TLS policy needs to set `ApplicationControlled` to `On`
in the [`TTLSEnvironmentAdvancedParms` section](https://www.ibm.com/support/knowledgecenter/SSLTBW_2.4.0/com.ibm.zos.v2r4.halz001/ttlsenvironmentadvancedparms.htm).

### Implementation

The library offers one class `org.zowe.commons.attls.AttlsContext` which provides all methods. You need to initialize it before using it.  To attach the socket's file description use the following code:

```java
AttlsContext attlsContext = new AttlsContext(<socket.fileDescriptor>, <alwaysLoadCertificate>);
System.out.println("AT-TLS connection status: " + attlsContext.getStatConn());
```

It can be used for both inbound and outbound communication.

Parameter `alwaysLoadCertificate` can improve performance. If you need in each request read the client
certificate, it is highly recommended set to `true`. It reduces calls to IOCTL. Otherwise,
set it to `false`.

You can also use class [org.zowe.commons.attls.InboundAttls](src/main/java/org/zowe/commons/attls/InboundAttls.java), which
allows to you store AT-TLS context in ThreadLocal and then access to inbound AT-TLS context from any different
part of application.

```java
import java.io.FileDescriptor;
import org.zowe.commons.attls.InboundAttls;

private static final Field FILE_DESCRIPTOR_FD;
static {
    FILE_DESCRIPTOR_FD = FileDescriptor.class.getDeclaredField("fd");
    FILE_DESCRIPTOR_FD.setAccessible(true);
}

// ...

FileDescriptor fd = <any way how to get FileDescriptor of socket>;
int fdVal = FILE_DESCRIPTOR_FD.getInt(fd);
InboundAttls.init(fdVal);

// ...

System.out.println("AT-TLS userID : " + InboundAttls.getUserId());
```

## Limitation of AT-TLS

AT-TLS supports a subset of protocols (HTTP and FTP). If you use a different protocol, the result can be different than
you expect (AT-TLS is defined, but not secure).
