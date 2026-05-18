"""Simula render_template passo a passo para encontrar onde user_search_clear_html some."""

def render_sim(template, **ctx):
    replaced = {}
    for key, value in ctx.items():
        before_placeholder_count = template.count('{{ ' + key + ' }}')
        if before_placeholder_count:
            template = template.replace('{{ ' + key + ' }}', str(value))
            after_count = template.count('{{ ' + key + ' }}')
            replaced[key] = (before_placeholder_count, after_count)
    return template, replaced

with open('templates/admin.html', encoding='utf-8') as f:
    t = open('templates/admin.html', encoding='utf-8').read()

# Contexto EXATO que show_admin passa (valores mínimos)
ctx = {
    'csrf_token': 'tok',
    'email_message': '',
    'settings_message': '',
    'users_message': '',
    'notification_email': '',
    'cleaning_user_rows': '',
    'status_options': '<opt>s</opt>',
    'location_options': '',
    'category_options': '<opt>c</opt>',
    'periodo_options': '<opt>p</opt>',
    'subcategory_options': '<opt>sub</opt>',
    'subcategory_options_json': '{}',
    'report_rows': '',
    'visible_count': '0',
    'pending_count': '0',
    'resolved_count': '0',
    'false_alert_count': '0',
    'top_cleaners_html': '',
    'top_course': '',
    'chart_payload': '[]',
    'user_search': '',
    'user_search_clear_html': '',
}

result, replaced = render_sim(t, **ctx)

# Verificar todos os placeholders substituídos e faltando
import re
remaining = re.findall(r'\{\{\s*[\w_]+\s*\}\}', result)

print('Keys replaced:')
for k, (b, a) in replaced.items():
    if b > 0:
        status = 'OK' if a == 0 else f'STILL {a} LEFT'
        print(f'  {k}: {b} occurrence(s) -> {status}')

print('\nRemaining {{ }}:', remaining if remaining else 'NONE')
print('\nuser_search related:')
print('  {{ user_search }} in result:', '{{ user_search }}' in result)
print('  {{ user_search_clear_html }} in result:', '{{ user_search_clear_html }}' in result)

# Check the user-search-form section in result
idx = result.find('user-search-form')
print('\n--- user-search-form section ---')
print(result[idx:idx+300])
