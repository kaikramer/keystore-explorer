/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.jr.ob.api.ValueReader;
import com.fasterxml.jackson.jr.ob.api.ValueWriter;
import com.fasterxml.jackson.jr.ob.impl.JSONReader;
import com.fasterxml.jackson.jr.ob.impl.JSONWriter;

/**
 * Custom JSON reader/writer because jackson-jr still has no support for Java 8 Date/Time API in 2023
 */
public class LocalDateConverter extends ValueReader implements ValueWriter {

    protected LocalDateConverter() {
        super(LocalDate.class);
    }

    @Override
    public void writeValue (JSONWriter context, JsonGenerator g, Object value) throws IOException {
        context.writeValue(((LocalDate) value).format(DateTimeFormatter.ISO_LOCAL_DATE));
    }

    @Override
    public Object read(JSONReader reader, JsonParser p) throws IOException {
        return LocalDate.parse(p.getText(), DateTimeFormatter.ISO_LOCAL_DATE);
    }

    @Override
    public Class<?> valueType () {
        return LocalDate.class;
    }

}
