# © Copyright 2021 HP Development Company, L.P.
import os
import falcon
from jinja2 import Environment, FileSystemLoader
from utils import db, Domain, Url, Extension, Tag, DomainTag, fn

db.connect()
if len(db.get_tables()) == 0:
    db.create_tables([Domain, Url, Extension, Tag, DomainTag])

colors = ["orange", "yellow", "olive", "green", "teal", "blue", "violet", "purple", "pink", "brown", "grey"]


def display_tagname(value):
    try:
        return value.tag.tag
    except Exception as e:
        return "None"


def load_template(name):
    file_loader = FileSystemLoader('app/templates')
    env = Environment(loader=file_loader)
    env.filters['display_tagname'] = display_tagname
    return env.get_template(name)


class SearchResource(object):
    def on_get(self, req, resp):
        template = load_template('search_results.html')
        error = ""
        urls = list()

        if ":" not in req.params['search']:
            error = "<b>Error: No valid search pattern!</b><br><br>Examples:<br><ul><li>url:hp.com</li><li>sha256:da3b8d283051c5615f359e376c0d908e6d0539bceed19e6a5667a27d01bf9fef</li><li>yara:protected_webshell</li><li>server:nginx</li></ul>"
        else:
            search_arr = req.params['search'].split(":")
            key = search_arr[0]
            value = "".join(search_arr[1:])

            if key == "sha256":
                urls = Url.select().where(Url.sha256 == value)
            elif key == "title":
                urls = Url.select().where(Url.title.contains(value))
            elif key == "url":
                urls = Url.select().where(Url.url.contains(value))
            elif key == "tag":
                urls = (Url.select().join(Domain).join(DomainTag).join(Tag).where(Tag.tag == value))
            else:
                urls = (Url.select().join(Extension).where((Extension.key == key) & (Extension.value.contains(value))))

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(error=error, urls=urls)


class DashboardResource(object):
    # TODO: Create useful charts as dashboard and show stats.

    def on_get(self, req, resp):
        template = load_template('dashboard.html')

        domains = Domain.select().count()
        urls = Url.select().count()

        tags = DomainTag.select(DomainTag.tag, fn.COUNT(DomainTag.tag).alias('count')).group_by(DomainTag.tag).order_by(fn.COUNT(DomainTag.tag).desc()).limit(5)
        hashes = Url.select(Url.sha256, fn.COUNT(Url.sha256).alias('count')).group_by(Url.sha256).order_by(fn.COUNT(Url.sha256).desc()).limit(5)

        i = 0
        for tag in tags:
            tag.color = colors[i % len(colors)]
            i += 1

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(dashboard_active='active', domains=domains, urls=urls, tags=tags, hashes=hashes)


class DomainResource(object):
    def on_get(self, req, resp):
        template = load_template('domains.html')
        domains = Domain.select()

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(domains_active='active', domains=domains)


class DomainDetailsResource(object):
    def on_delete(self, req, resp, did):
        domain = Domain.get(Domain.id == did)

        urls = Url.select().where(Url.domain == domain)
        for u in urls:
            ext_query = Extension.delete().where(Extension.url == u)
            ext_query.execute()

        query = Url.delete().where(Url.domain == domain)
        query.execute()

        query_domtag = DomainTag.delete().where(DomainTag.domain == domain)
        query_domtag.execute()

        domain.delete_instance()

        template = load_template('domains.html')
        domains = Domain.select()
        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(domains_active='active', domains=domains)

    def on_get(self, req, resp, did):
        template = load_template('domain_details.html')
        domain = Domain.get(Domain.id == did)
        urls = Url.select().where(Url.domain == domain)
        tags = (Tag.select().join(DomainTag).join(Domain).where(Domain.id == did))

        i = 0
        for tag in tags:
            tag.color = colors[i % len(colors)]
            i += 1

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(domain=domain, urls=urls, tags=tags)

    def on_post(self, req, resp, did):
        if "delete" in req.params:
            self.on_delete(req, resp, did)
            return
        template = load_template('domain_details.html')

        domain = Domain.get(Domain.id == did)
        domain.description = req.params['description']
        domain.save()

        urls = Url.select().where(Url.domain == domain)
        tags = (Tag.select().join(DomainTag).join(Domain).where(Domain.id == did))

        i = 0
        for tag in tags:
            tag.color = colors[i % len(colors)]
            i += 1

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(domain=domain, urls=urls, tags=tags)


class UrlResource(object):
    def on_get(self, req, resp):
        template = load_template('urls.html')
        urls = Url.select()

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(urls_active='active', urls=urls)


class UrlDetailsResource(object):
    def on_delete(self, req, resp, uid):
        url = Url.get(Url.id == uid)

        ext_query = Extension.delete().where(Extension.url == url)
        ext_query.execute()

        url.delete_instance()

        template = load_template('urls.html')
        urls = Url.select()
        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(urls_active='active', urls=urls)

    def on_get(self, req, resp, uid):
        template = load_template('url_details.html')
        url = Url.get(Url.id == uid)
        extensions = Extension.select().where(Extension.url == url)

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(url=url, extensions=extensions)

    def on_post(self, req, resp, uid):
        if "delete" in req.params:
            self.on_delete(req, resp, uid)
            return
        template = load_template('url_details.html')

        url = Url.get(Url.id == uid)
        extensions = Extension.select().where(Extension.url == url)

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = template.render(url=url)


# api initialization
app = falcon.API()
app.req_options.auto_parse_form_urlencoded = True
dashboard = DashboardResource()
domains = DomainResource()
domain_details = DomainDetailsResource()
urls = UrlResource()
url_details = UrlDetailsResource()
search = SearchResource()

app.add_route('/', dashboard)
app.add_route('/domain', domains)
app.add_route('/domain/{did:int}', domain_details)

app.add_route('/url', urls)
app.add_route('/url/{uid:int}', url_details)

app.add_route('/search', search)
