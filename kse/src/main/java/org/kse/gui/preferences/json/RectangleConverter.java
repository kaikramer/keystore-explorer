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

package org.kse.gui.preferences.json;

import java.awt.Rectangle;
import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.jr.ob.api.ValueReader;
import com.fasterxml.jackson.jr.ob.api.ValueWriter;
import com.fasterxml.jackson.jr.ob.impl.JSONReader;
import com.fasterxml.jackson.jr.ob.impl.JSONWriter;

/**
 * Custom JSON reader/writer because java.awt.Rectangle causes issues with jackson
 */
public class RectangleConverter extends ValueReader implements ValueWriter {

    protected RectangleConverter() {
        super(Rectangle.class);
    }

    @Override
    public void writeValue(JSONWriter context, JsonGenerator g, Object value) throws IOException {
        Rectangle rectangle = (Rectangle) value;
        g.writeStartObject();
        g.writeNumberField("x", rectangle.x);
        g.writeNumberField("y", rectangle.y);
        g.writeNumberField("width", rectangle.width);
        g.writeNumberField("height", rectangle.height);
        g.writeEndObject();
    }

    @Override
    public Object read(JSONReader reader, JsonParser p) throws IOException {
        Map<String, Object> map = reader.readMap();
        return new Rectangle((Integer) map.get("x"),
                             (Integer) map.get("y"),
                             (Integer) map.get("width"),
                             (Integer) map.get("height"));
    }

    @Override
    public Class<Rectangle> valueType() { return Rectangle.class; }
}
