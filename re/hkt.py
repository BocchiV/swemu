"""Havok 2012 binary tagfile reader (magic CAB00D1E D011FACE, "hk_2012.2.0-r1")
for the client's World/Navmesh/*.hkt (hkaiNavMesh). Format worked out on the
CZ43 file: zigzag varints, string table, class metadata, objects with member
bitfields; struct arrays are stored member by member.

    from hkt import load_navmesh
    verts, faces = load_navmesh(bytes)   # faces: list of vertex index lists
"""
import struct

T_VOID, T_BYTE, T_INT, T_REAL, T_VEC4, T_VEC8, T_VEC12, T_VEC16, T_OBJECT, T_STRUCT, T_CSTRING = range(11)
T_ARRAY, T_TUPLE = 0x10, 0x20


class Reader:
    def __init__(self, b):
        assert b[:8] == bytes.fromhex("1e0db0cacefa11d0"), "not a Havok binary tagfile"
        self.b, self.o = b, 8
        self.strings = ["", None]
        self.classes = [None]
        self.objects = []
        self.version = 0

    def byte(self):
        v = self.b[self.o]
        self.o += 1
        return v

    def uvar(self):
        v = shift = 0
        while True:
            c = self.byte()
            v |= (c & 0x7F) << shift
            shift += 7
            if not c & 0x80:
                return v

    def int(self):
        u = self.uvar()
        return -(u >> 1) if u & 1 else u >> 1

    def string(self):
        n = self.int()
        if n > 0:
            s = self.b[self.o:self.o + n].decode("latin1")
            self.o += n
            self.strings.append(s)
            return s
        return self.strings[-n]

    def floats(self, n):
        v = struct.unpack_from(f"<{n}f", self.b, self.o)
        self.o += 4 * n
        return v

    # --- metadata ---------------------------------------------------------
    def read_type(self):
        t = self.int()
        base = t & 0xF
        sub = None
        if base in (T_OBJECT, T_STRUCT):
            sub = self.string()
        tup = self.int() if t & T_TUPLE else 0
        return (t, sub, tup)

    def read_class(self):
        name = self.string()
        ver = self.int()
        parent = self.int()
        n = self.int()
        members = [(self.string(), self.read_type()) for _ in range(n)]
        self.classes.append({"name": name, "version": ver, "parent": parent, "members": members})

    def all_members(self, ci):
        c = self.classes[ci]
        out = self.all_members(c["parent"]) if c["parent"] else []
        return out + c["members"]

    def class_index(self, name):
        for i, c in enumerate(self.classes):
            if c and c["name"] == name:
                return i
        raise KeyError(name)

    # --- values -----------------------------------------------------------
    def bitfield(self, n):
        nb = (n + 7) // 8
        bits = self.b[self.o:self.o + nb]
        self.o += nb
        return [bool(bits[i // 8] >> (i % 8) & 1) for i in range(n)]

    def read_object_body(self, ci):
        mem = self.all_members(ci)
        present = self.bitfield(len(mem))
        obj = {"__class__": self.classes[ci]["name"]}
        for (name, ty), p in zip(mem, present):
            if p:
                obj[name] = self.read_value(ty)
        return obj

    def read_object(self):
        tag = self.int()
        if tag == 6:  # null
            return None
        if tag == 5:  # backref
            return self.objects[self.int()]
        if tag in (3, 4):
            ci = self.int()
            slot = len(self.objects)
            if tag == 4:
                self.objects.append(None)
            obj = self.read_object_body(ci)
            if tag == 4:
                self.objects[slot] = obj
            return obj
        raise ValueError(f"bad object tag {tag} at {self.o}")

    def read_value(self, ty):
        t, sub, tup = ty
        if t & T_ARRAY:
            n = self.int()
            return self.read_array((t & ~T_ARRAY, sub, tup), n)
        if t & T_TUPLE:
            return [self.read_value((t & ~T_TUPLE, sub, 0)) for _ in range(tup)]
        return self.read_scalar(t, sub)

    def read_scalar(self, t, sub):
        if t == T_BYTE:
            return self.byte()
        if t == T_INT:
            return self.int()
        if t == T_REAL:
            return self.floats(1)[0]
        if t in (T_VEC4, T_VEC8, T_VEC12, T_VEC16):
            return self.floats({T_VEC4: 4, T_VEC8: 8, T_VEC12: 12, T_VEC16: 16}[t])
        if t == T_OBJECT:
            # Tagfile v4: references are object indices (0 = null); the
            # objects themselves follow at top level in order.
            return ("ref", self.int())
        if t == T_STRUCT:
            return self.read_object_body(self.class_index(sub))
        if t == T_CSTRING:
            return self.string()
        if t == T_VOID:
            return None
        raise ValueError(f"type {t}")

    def read_array(self, ty, n):
        t, sub, tup = ty
        if n == 0:
            return []
        if t & T_TUPLE:
            inner = (t & ~T_TUPLE, sub, 0)
            if inner[0] in (T_REAL,):
                flat = self.floats(n * tup)
                return [flat[i * tup:(i + 1) * tup] for i in range(n)]
            flat = self.read_array(inner, n * tup)
            return [flat[i * tup:(i + 1) * tup] for i in range(n)]
        if t == T_BYTE:
            v = list(self.b[self.o:self.o + n])
            self.o += n
            return v
        if t == T_INT:
            self.int()  # element width (4 = 32 bit), then zigzag varints
            return [self.int() for _ in range(n)]
        if t == T_REAL:
            return list(self.floats(n))
        if t in (T_VEC4, T_VEC8, T_VEC12, T_VEC16):
            # Vector arrays carry a varint with the stored lane count (3 or 4
            # for hkVector4) before the floats.
            k = self.int()
            flat = self.floats(n * k)
            return [flat[i * k:(i + 1) * k] for i in range(n)]
        if t == T_OBJECT:
            return [("ref", self.int()) for _ in range(n)]
        if t == T_CSTRING:
            return [self.string() for _ in range(n)]
        if t == T_STRUCT:
            ci = self.class_index(sub)
            mem = self.all_members(ci)
            present = self.bitfield(len(mem))
            cols = {}
            for (name, mty), p in zip(mem, present):
                if p:
                    cols[name] = self.read_value_array(mty, n)
            return [{k: v[i] for k, v in cols.items()} for i in range(n)]
        raise ValueError(f"array type {t}")

    def read_value_array(self, ty, n):
        t, sub, tup = ty
        if t & T_ARRAY:
            return [self.read_value(ty) for _ in range(n)]
        return self.read_array(ty, n)

    def parse(self):
        root = None
        while self.o < len(self.b):
            tag = self.int()
            if tag == 1:
                self.version = self.int()
                self.string()
            elif tag == 2:
                self.read_class()
            elif tag in (3, 4):
                ci = self.int()
                obj = self.read_object_body(ci)
                self.objects.append(obj)
                root = root or obj
            elif tag == 7:
                break
            elif tag == 0:
                continue
            else:
                raise ValueError(f"bad top tag {tag} at {self.o}")
        return root


def resolve(r, obj, seen=None):
    """Replace ("ref", i) with the i-th top-level object (1-based)."""
    seen = seen if seen is not None else set()
    if isinstance(obj, dict):
        if id(obj) in seen:
            return obj
        seen.add(id(obj))
        for k, v in obj.items():
            obj[k] = resolve(r, v, seen)
        return obj
    if isinstance(obj, list):
        return [resolve(r, v, seen) for v in obj]
    if isinstance(obj, tuple) and len(obj) == 2 and obj[0] == "ref":
        i = obj[1]
        return r.objects[i - 1] if 0 < i <= len(r.objects) else None
    return obj


def find(obj, cls, seen=None):
    seen = seen if seen is not None else set()
    if isinstance(obj, dict):
        if id(obj) in seen:
            return None
        seen.add(id(obj))
        if obj.get("__class__") == cls:
            return obj
        vals = obj.values()
    elif isinstance(obj, list):
        vals = obj
    else:
        return None
    for v in vals:
        r = find(v, cls, seen)
        if r is not None:
            return r
    return None


def load_navmesh(b):
    r = Reader(b)
    r.parse()
    for o in r.objects:
        resolve(r, o)
    nm = next((o for o in r.objects if o and o.get("__class__") == "hkaiNavMesh"), None)
    assert nm is not None, "no hkaiNavMesh"
    verts = [tuple(v[:3]) for v in nm.get("vertices", [])]
    edges = nm.get("edges", [])
    faces = []
    for f in nm.get("faces", []):
        s, n = f.get("startEdgeIndex", 0), f.get("numEdges", 0)
        faces.append([edges[s + i].get("a", 0) for i in range(n)])
    return verts, faces


if __name__ == "__main__":
    import sys, maze_data as md
    b = md.read("data09", f"World/Navmesh/{sys.argv[1]}.hkt", md._pw())
    r = Reader(b)
    root = r.parse()
    print("consumed", r.o, "of", len(b), "classes", len(r.classes) - 1)
    for c in r.classes[1:]:
        print(" ", c["name"], [(m[0], m[1][0]) for m in c["members"]])
    v, f = load_navmesh(b)
    print("verts", len(v), "faces", len(f), v[:3], f[:3])
