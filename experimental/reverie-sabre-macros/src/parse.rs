/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use darling::FromMeta;
use heck::CamelCase;
use quote::format_ident;
use syn::parse::Parse;
use syn::parse::ParseStream;

use crate::Detour;
use crate::DetourAttrs;
use crate::Tool;

fn parse_method(method: &syn::ImplItemMethod, attribute: &syn::Attribute) -> syn::Result<Detour> {
    let meta = attribute.parse_meta()?;
    let method_attrs = DetourAttrs::from_meta(&meta)?;
    let mut outer_item = method.clone();
    outer_item.attrs.retain(|a| !a.path.is_ident("detour"));
    Ok(Detour {
        outer_item,
        callback_name: format_ident!("{}_{}_callback", method_attrs.lib, method_attrs.func),
        stub_name: format_ident!("{}_{}_stub", method_attrs.lib, method_attrs.func),
        detoured_definition_name: format_ident!("{}", method.sig.ident.to_string()),
        undetoured_field_name: format_ident!(
            "{}_{}_UNDETOURED",
            method_attrs.lib.clone().to_uppercase(),
            method_attrs.func.clone().to_uppercase()
        ),
        undetoured_method_name: format_ident!(
            "{}_{}_undetoured",
            method_attrs.lib,
            method_attrs.func
        ),
        detoured_function_type_name: syn::Ident::new(
            format!(
                "{}{}Func",
                method_attrs.lib.clone().to_uppercase(),
                method_attrs.func.clone().to_uppercase()
            )
            .as_str()
            .to_camel_case()
            .as_str(),
            proc_macro2::Span::call_site(),
        ),
        attrs: method_attrs,
    })
}

fn filter_map_attribute<'a>(
    method: &'a syn::ImplItemMethod,
    attribute: &str,
) -> Option<&'a syn::Attribute> {
    method.attrs.iter().find(|a| a.path.is_ident(attribute))
}

impl Parse for Tool {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut impl_node: syn::ItemImpl = input.parse()?;

        let detour_methods: Result<Vec<_>, _> = impl_node
            .items
            .iter()
            .filter_map(|n| match n {
                syn::ImplItem::Method(method_impl) => filter_map_attribute(method_impl, "detour")
                    .map(|a| parse_method(method_impl, a)),
                _ => None,
            })
            .collect();

        impl_node.items.retain(|m| match m {
            syn::ImplItem::Method(method) => filter_map_attribute(method, "detour").is_none(),
            _ => true,
        });

        Ok(Self {
            outer_item: impl_node,
            detoured_methods: detour_methods?,
        })
    }
}
