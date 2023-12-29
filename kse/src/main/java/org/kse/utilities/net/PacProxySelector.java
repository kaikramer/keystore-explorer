/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.kse.utilities.net;

import static java.util.Collections.singletonList;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

import org.apache.commons.io.IOUtils;
import org.kse.utilities.TriFunction;
import org.kse.utilities.VarFunction;
import org.kse.version.JavaVersion;

/**
 * Proxy Selector for Proxy Automatic Configuration (PAC).
 */
public class PacProxySelector extends ProxySelector {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/utilities/net/resources");

    private Invocable pacScript;
    private final URI pacURI;
    private final Map<URI, List<Proxy>> uriToProxiesCache = new HashMap<>();

    /**
     * Class filter to restrict access to JRE from PAC script
     */
    // TODO comment in again when support for Java 8 is dropped
//    static class PacClassFilter implements ClassFilter {
//        @Override
//        public boolean exposeToScripts(String s) {
//            return false;
//        }
//    }

    /**
     * Construct PacProxySelector using an Automatic proxy configuration URL.
     * Loads the PAC script from the supplied URL.
     *
     * @param pacURI Automatic proxy configuration URL
     */
    public PacProxySelector(URI pacURI) {
        if (pacURI == null) {
            throw new IllegalArgumentException("PAC URL is missing");
        }

        this.pacURI = pacURI;

        // As load and compile of pac scripts is time-consuming we do this on first call to select
    }

    /**
     * Get a list of proxies for the supplied URI.
     *
     * @param uri The URI that a connection is required to
     * @return List of proxies; if there are any issues with the PAC returns 'no proxy'
     */
    @Override
    public List<Proxy> select(URI uri) {
        if (pacScript == null) {
            try {
                pacScript = compilePacScript(loadPacScript(pacURI));
            } catch (PacProxyException ex) {
                ex.printStackTrace();
                return singletonList(Proxy.NO_PROXY);
            }
        }

        if (uriToProxiesCache.containsKey(uri)) {
            return uriToProxiesCache.get(uri);
        }

        String pacFunctionReturn = null;

        try {
            pacFunctionReturn = (String) pacScript.invokeFunction("FindProxyForURL", uri.toString(), uri.getHost());
        } catch (Exception ex) {
            ex.printStackTrace();
            return singletonList(Proxy.NO_PROXY);
        }

        if (pacFunctionReturn == null) {
            return singletonList(Proxy.NO_PROXY);
        }

        List<Proxy> proxies = new ArrayList<>(parsePacProxies(pacFunctionReturn));

        if (proxies.isEmpty()) {
            proxies.add(Proxy.NO_PROXY);
        }

        uriToProxiesCache.put(uri, proxies);

        return proxies;
    }

    private String loadPacScript(URI pacURI) throws PacProxyException {
        URLConnection connection = null;

        // Save existing default proxy selector...
        ProxySelector defaultProxySelector = ProxySelector.getDefault();

        try {
            // ...and set use of no proxy selector. We don't want to try and use any proxy to get the pac script
            ProxySelector.setDefault(new NoProxySelector());

            URL latestVersionUrl = pacURI.toURL();
            connection = latestVersionUrl.openConnection();

            try (InputStreamReader isr = new InputStreamReader(connection.getInputStream());
                 StringWriter sw = new StringWriter()) {
                IOUtils.copy(isr, sw);
                return sw.toString();
            }
        } catch (IOException ex) {
            throw new PacProxyException(
                    MessageFormat.format(res.getString("NoLoadPacScript.exception.message"), pacURI), ex);
        } finally {
            // Restore saved default proxy selector
            ProxySelector.setDefault(defaultProxySelector);

            if ((connection instanceof HttpURLConnection)) {
                ((HttpURLConnection) connection).disconnect();
            }
        }
    }

    private Invocable compilePacScript(String pacScript) throws PacProxyException {
        try {
            ScriptEngine jsEngine;

            // Nashorn was removed in Java 15, the standalone Nashorn uses different packages and is compiled for Java 11
            // TODO remove this when support for Java 8 is dropped
            if (JavaVersion.getJreVersion().isAtLeast(JavaVersion.JRE_VERSION_15)) {
                jsEngine = getScriptEngine("org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory",
                                           "org.openjdk.nashorn.api.scripting.ClassFilter");
            } else {
                jsEngine = getScriptEngine("jdk.nashorn.api.scripting.NashornScriptEngineFactory",
                                           "jdk.nashorn.api.scripting.ClassFilter");
            }

            jsEngine.put("alert", (Consumer<String>) PacHelperFunctions::alert);
            jsEngine.put("dnsDomainIs", (BiFunction<String, String, Boolean>) PacHelperFunctions::dnsDomainIs);
            jsEngine.put("dnsDomainLevels", (Function<String, Integer>) PacHelperFunctions::dnsDomainLevels);
            jsEngine.put("dnsResolve", (Function<String, String>) PacHelperFunctions::dnsResolve);
            jsEngine.put("isResolvable", (Function<String, Boolean>) PacHelperFunctions::isResolvable);
            jsEngine.put("myIpAddress", (Supplier<String>) PacHelperFunctions::myIpAddress);
            jsEngine.put("isPlainHostName", (Function<String, Boolean>) PacHelperFunctions::isPlainHostName);
            jsEngine.put("localHostOrDomainIs", (BiFunction<String, String, Boolean>) PacHelperFunctions::localHostOrDomainIs);
            jsEngine.put("shExpMatch", (BiFunction<String, String, Boolean>) PacHelperFunctions::shExpMatch);
            jsEngine.put("isInNet", (TriFunction<String, String, String, Boolean>) PacHelperFunctions::isInNet);
            jsEngine.put("dateRange", (VarFunction<Object, Boolean>) PacHelperFunctions::dateRange);
            jsEngine.put("weekdayRange", (VarFunction<Object, Boolean>) PacHelperFunctions::weekdayRange);
            jsEngine.put("timeRange", (VarFunction<Object, Boolean>) PacHelperFunctions::timeRange);

            // disable access to engine and context
            jsEngine.eval("Object.defineProperty(this, 'engine', {});");
            jsEngine.eval("Object.defineProperty(this, 'context', {});");
            jsEngine.eval("delete this.__noSuchProperty__;");

            jsEngine.eval(pacScript);

            return (Invocable) jsEngine;
        } catch (ScriptException ex) {
            throw new PacProxyException(res.getString("NoCompilePacScript.exception.message"), ex);
        }
    }

    private ScriptEngine getScriptEngine(String nashornScriptEngineFactoryClass, String classFilterClass) {
        // NashornScriptEngineFactory nashornScriptEngineFactory = new NashornScriptEngineFactory();
        // ScriptEngine jsEngine = nashornScriptEngineFactory.getScriptEngine(new PacClassFilter());
        try {
            Class<?> nashornScriptEngineFactory = Class.forName(nashornScriptEngineFactoryClass);
            Class<?> classFilter = Class.forName(classFilterClass);

            Object classFilterProxy = java.lang.reflect.Proxy.newProxyInstance(
                    PacProxySelector.class.getClassLoader(), new Class[] { classFilter }, (proxy, method, args) -> {
                        if (method.getName().equals("exposeToScripts")) {
                            return Boolean.FALSE;
                        }
                        return null;
                    });

            Method getScriptEngine = nashornScriptEngineFactory.getMethod("getScriptEngine", classFilter);
            return (ScriptEngine) getScriptEngine.invoke(nashornScriptEngineFactory.newInstance(), classFilterProxy);
        } catch (ClassNotFoundException | NoSuchMethodException | InvocationTargetException | IllegalAccessException |
                 InstantiationException e) {
            throw new RuntimeException(e);
        }
    }

    private List<Proxy> parsePacProxies(String pacFunctionReturn) {
        ArrayList<Proxy> proxies = new ArrayList<>();

        // PAC function return delimits different proxies by ';'
        StringTokenizer strTok = new StringTokenizer(pacFunctionReturn, ";");

        while (strTok.hasMoreTokens()) {
            String pacFunctionReturnElement = strTok.nextToken().trim();

            if (!pacFunctionReturnElement.isEmpty()) {
                Proxy proxy = parsePacProxy(pacFunctionReturnElement);

                if (proxy != null) {
                    proxies.add(proxy);
                }
            }
        }

        return proxies;
    }

    private Proxy parsePacProxy(String pacProxy) {
        String[] split = pacProxy.split(" ", 0);

        String proxyTypeStr = split[0];
        Proxy.Type proxyType = null;

        switch (proxyTypeStr) {
        case "DIRECT":
            return Proxy.NO_PROXY;
        case "PROXY":
        case "HTTP":
        case "HTTPS":
            proxyType = Proxy.Type.HTTP;
            break;
        case "SOCKS":
        case "SOCKS4":
        case "SOCKS5":
            proxyType = Proxy.Type.SOCKS;
            break;
        default:
            return null;
        }

        if (split.length != 2) {
            return null;
        }

        String address = split[1];
        split = address.split(":", 0);
        String host = null;
        int port = 80;

        if (split.length == 1) {
            host = split[0];
        } else if (split.length == 2) {
            host = split[0];

            try {
                port = Integer.parseInt(split[1]);
            } catch (NumberFormatException ex) {
                return null;
            }
        } else {
            return null;
        }

        return new Proxy(proxyType, new InetSocketAddress(host, port));
    }

    /**
     * Connection failed. Do nothing.
     *
     * @param uri           The URI that the proxy at socketAddress failed to serve
     * @param socketAddress The socket address of the proxy/SOCKS server
     * @param ioException   The I/O exception thrown when the connection failed
     */
    @Override
    public void connectFailed(URI uri, SocketAddress socketAddress, IOException ioException) {
        /*
         * Do nothing. Documentation of base class ProxySelector suggests that
         * this method may be used to affect what the select method returns.
         * This is not relevant to us.
         */
    }

    /**
     * Get Automatic proxy configuration URL.
     *
     * @return PAC URI
     */
    public URI getPacURI() {
        return pacURI;
    }

    /**
     * Is this PacProxySelector object equal to another object?
     *
     * @param object Object to compare PacProxySelector with.
     * @return true if the equal, false otherwise.
     */
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }

        if (!(object instanceof PacProxySelector)) {
            return false;
        }

        PacProxySelector cmpPacProxySelector = (PacProxySelector) object;

        return this.getPacURI().equals(cmpPacProxySelector.getPacURI());
    }
}
